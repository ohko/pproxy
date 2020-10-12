package pproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProxyInterface ...
type ProxyInterface interface {
	// OnAuth 账号验证，返回error判断是否有错误，返回string为二级代理地址
	OnAuth(user, password string) (string, error)
	// OnSuccess 代理建立成功，返回客户端、代理端连接
	OnSuccess(clientConn net.Conn, serverConn net.Conn)
}

// PProxy 中继HTTP代理
type PProxy struct {
	Client net.Conn
	PI     ProxyInterface

	reader    *bufio.Reader
	firstLine string
}

// Handshake ...
func (o *PProxy) Handshake() (net.Conn, error) {
	// check socks5/http
	prefix := make([]byte, 1)
	if _, err := o.Client.Read(prefix); err != nil {
		return nil, err
	}

	if prefix[0] == 0x5 {
		// log.Println("socks5")
		return o.handshakeSocks5(prefix)
	}

	// log.Println("http")
	return o.handshakeHTTP(prefix)
}

// hand socks5 proxy
func (o *PProxy) handshakeSocks5(prefix []byte) (net.Conn, error) {
	var b [1024]byte
	copy(b[:], prefix)

	// 客户端:请求代理设置
	// 05 01 00 共3字节，这种是要求匿名代理
	// 05 01 02 共3字节，这种是要求以用户名密码方式验证代理
	// 05 02 00 02 共4字节，这种是要求以匿名或者用户名密码方式代理
	n, err := o.Client.Read(b[len(prefix):])
	if err != nil {
		return nil, err
	}
	n += len(prefix)
	// log.Printf("客户端获取设置: % x", b[:n])

	// 服务端:如果socks5代理允许匿名那么就返回05 00两个字节，如果要求验证就返回05 02两个字节。
	o.Client.Write([]byte{0x05, 0x02})

	// 当上面socks5返回05 02两个字节后
	// 客户端发送01 06 6C 61 6F  74 73 65 06 36 36 36 38 38 38
	// 1、01固定的
	// 2、06这一个字节这是指明用户名长度，说明后面紧跟的6个字节就是用户名
	// 3、6C 61 6F 74 73 65这就是那6个是用户名，是laotse的ascii
	// 4、又一个06共1个字节指明密码长度，说明后面紧跟的6个字节就是密码
	// 5、36 36 36 38 38 38就是这6个是密码，666888的ascii。
	// 6、假如这后面还有字节，一律无视。
	n, err = o.Client.Read(b[:])
	if err != nil {
		return nil, err
	}
	if n < 3 {
		return nil, errors.New("socks5 connect error")
	}
	if b[0] != 0x1 {
		return nil, errors.New("need user and password")
	}
	user := string(b[2 : 2+b[1]])
	password := string(b[3+b[1] : 3+b[1]*2])

	// 服务器验证失败，直接关闭连接即可
	// 服务器验证成功后，就发送01 00给客户端，后面和匿名代理一样了
	newAuth, err := o.PI.OnAuth(user, password)
	if err != nil {
		return nil, err
	}
	o.Client.Write([]byte{0x01, 0x00})

	// 二级代理
	if newAuth != "" && strings.HasPrefix(newAuth, "socks5") {
		nn, _, err := o.level2("", "", newAuth)
		if err != nil {
			o.PI.OnSuccess(o.Client, nn)
		}
		return nn, err
	}

	// 代理IP: 05 01 00 03 13 77  65 62 2E 73 6F 75 72 63  65 66 6F 72 67 65 2E 6E  65 74 00 16
	// 1、05固定
	// 2、01说明是tcp
	// 3、00固定
	// 4、03说明后面跟着的是域名而不是ip地址，由socks5服务器进行dns解析
	// 5、13前面指明了是域名，那么0x13（19字节）是域名字符长度
	// 6、77 65 62 2E 73 6F 75 72 63 65 66 6F 72 67 65 2E 6E 65 74 就这19个是域名web.sourceforge.net的ascii。
	// 7、00 16端口，即为22端口。
	// 代理域名: 05 01 00 01 CA 6C 16 05 00 50
	// 1、05固定
	// 2、01说明tcp
	// 3、00固定
	// 4、01说明是ip地址
	// 5、CA 6C 16 05就是202.108.22.5了，百度ip
	// 6、00 50端口，即为80端口
	n, err = o.Client.Read(b[:])
	// log.Printf("客户端获取设置: % x", b[:n])
	if err != nil {
		return nil, err
	}
	if n < 3 {
		return nil, errors.New("socks5 connect error")
	}
	if b[0] != 0x5 {
		return nil, errors.New("proxy command error")
	}
	// log.Printf("客户端请求代理: % x", b[:n])

	var addr string
	switch b[3] {
	case 0x01: // IP模式
		sip := sockIP{}
		if err := binary.Read(bytes.NewReader(b[4:n]), binary.BigEndian, &sip); err != nil {
			return nil, err
		}
		addr = sip.toAddr()
		// log.Printf("IP代理模式: %s", addr)
	case 0x03: // 域名模式
		host := string(b[5 : n-2])
		var port uint16
		err = binary.Read(bytes.NewReader(b[n-2:n]), binary.BigEndian, &port)
		if err != nil {
			return nil, err
		}
		addr = fmt.Sprintf("%s:%d", host, port)
		// log.Printf("域名要求代理: %s", addr)
	default: // 未知模式
		return nil, fmt.Errorf("未知模式")
	}

	// 二级代理
	if newAuth != "" && strings.HasPrefix(newAuth, "http") {
		nn, _, err := o.level2("CONNECT "+addr+" HTTP/1.1\r\nHost: "+addr+"\r\nProxy-Authorization: Basic eDp5\r\n\r\n", "Proxy-Authorization: Basic eDp5\r\n", newAuth)
		if err != nil {
			o.PI.OnSuccess(o.Client, nn)
		}
		b := make([]byte, 1024)
		_, err = nn.Read(b)
		if err != nil {
			return nil, err
		}
		o.Client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		o.PI.OnSuccess(o.Client, nn)
		return nn, err
	}

	// 建立连接
	nn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// 返回成功建立代理: 05 00 00 01 C0 A8  00 08 16 CE共10个字节
	// 1、05 00 00 01固定的
	// 2、后面8个字节可以全是00，也可以发送socks5服务器连接远程主机用到的ip地址和端口，比如这里C0 A8 00 08，就是192.168.0.8，16 CE即5838端口，即是socks5服务器用5838端口去连接百度的80端口。
	o.Client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	o.PI.OnSuccess(o.Client, nn)
	return nn, nil
}

// socks5二级代理
func (o *PProxy) socks5Level2(newAuth string) (net.Conn, error) {
	var b [1024]byte

	// log.Println("二级代理:", newAuth)
	u, err := url.Parse(newAuth)
	if err != nil {
		return nil, err
	}

	// Dail
	newConn, err := net.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	// 匿名/登录
	if _, err := newConn.Write([]byte{0x5, 0x2, 0x0, 0x2}); err != nil {
		return nil, err
	}
	n, err := newConn.Read(b[:])
	if n < 2 {
		return nil, errors.New("socks5 connect error")
	}
	if b[0] != 0x5 {
		return nil, errors.New("proxy command error")
	}
	if b[1] != 0x0 && b[1] != 2 {
		return nil, errors.New("login return unknown command")
	}

	// 登录
	if b[1] == 0x2 {
		buffer := bytes.NewBuffer(nil)
		buffer.WriteByte(1)
		buffer.WriteRune(rune(len(u.User.Username())))
		buffer.Write([]byte(u.User.Username()))
		p, _ := u.User.Password()
		buffer.WriteRune(rune(len(p)))
		buffer.Write([]byte(p))
		if _, err := newConn.Write(buffer.Bytes()); err != nil {
			return nil, err
		}

		// CopyHelper(newConn, o.Client)
		// return newConn, nil
		n, err = newConn.Read(b[:])
		if n < 2 {
			return nil, errors.New("socks5 connect error")
		}
		if b[0] != 0x1 && b[1] != 0 {
			return nil, errors.New("socks5 login error")
		}
	}

	return newConn, nil
}

// hand http proxy
func (o *PProxy) handshakeHTTP(prefix []byte) (net.Conn, error) {
	// read first line
	o.reader = bufio.NewReader(o.Client)
	l, err := o.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	o.firstLine = string(prefix) + l
	arr := strings.Split(o.firstLine, " ")

	// CONNECT/GET/POST/...
	if arr[0] == "CONNECT" {
		return o.typeConnect(arr)
	} else if arr[0] == "GET" || arr[0] == "POST" ||
		arr[0] == "PUT" || arr[0] == "DELETE" || arr[0] == "HEAD" || arr[0] == "OPTIONS" {
		return o.typeOther(arr)
	}

	// unknown
	return nil, errors.New("Unknown header:" + o.firstLine)
}

// CONNECT
func (o *PProxy) typeConnect(firstLineArr []string) (net.Conn, error) {
	// auth
	newConn, _, err := o.checkAuth(&url.URL{Host: firstLineArr[1]})
	if err != nil {
		return nil, err
	}

	// p-proxy
	if newConn != nil {
		return newConn, nil
	}

	// Dail
	n, err := net.Dial("tcp", firstLineArr[1])
	if err == nil {
		if _, err := o.Client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return nil, err
		}
		o.PI.OnSuccess(o.Client, n)
	}
	return n, err
}

// GET/POST/PUT/...
func (o *PProxy) typeOther(firstLineArr []string) (net.Conn, error) {
	u, err := url.Parse(firstLineArr[1])
	if err != nil {
		return nil, err
	}
	if !strings.Contains(u.Host, ":") {
		u.Host += ":80"
	}

	// auth
	newConn, header, err := o.checkAuth(u)
	if err != nil {
		return nil, err
	}

	// p-proxy
	if newConn != nil {
		return newConn, nil
	}

	firstLine := strings.ReplaceAll(o.firstLine, u.Scheme+"://"+u.Host, "")

	// Dail
	n, err := net.Dial("tcp", u.Host)
	if err == nil {
		if _, err := n.Write([]byte(firstLine + header)); err != nil {
			return nil, err
		}
		o.PI.OnSuccess(o.Client, n)
	}
	return n, err
}

// return newConn, header, error
func (o *PProxy) checkAuth(uri *url.URL) (net.Conn, string, error) {
	originHeader := ""
	header := ""
	authLine := ""
	for {
		l, err := o.reader.ReadString('\n')
		if err != nil {
			return nil, "", err
		}
		originHeader += l

		// Proxy-Authorization: Basic eDp5
		if strings.HasPrefix(l, "Proxy-Authorization") {
			authLine = l
			continue
		}

		// Proxy-Connection: Keep-Alive
		if strings.HasPrefix(l, "Proxy-") {
			continue
		}

		header += l

		// end
		if len(strings.TrimSpace(l)) == 0 {
			break
		}
	}

	// analy user and password
	user, password := "", ""
	if authLine != "" {
		if strings.Contains(authLine, " Basic ") {
			tmp := strings.Split(authLine, " ")
			up, err := base64.StdEncoding.DecodeString(tmp[2])
			if err != nil {
				return nil, "", err
			}
			upArr := strings.Split(string(up), ":")
			if len(upArr) != 2 {
				return nil, "", errors.New("user:password error:" + string(up))
			}
			user, password = upArr[0], upArr[1]
		}
	}

	// callback auth and get new proxy setting if need
	newAuth, err := o.PI.OnAuth(user, password)
	if err != nil {
		return nil, "", err
	}

	// log.Println("originHeader:", originHeader)
	// log.Println("header:", header)

	// 二级代理
	if newAuth != "" {
		nn, newHeader, err := o.level2(originHeader, authLine, newAuth)

		if strings.HasPrefix(newAuth, "socks5") {
			up := strings.Split(uri.Host, ":")
			port, _ := strconv.Atoi(up[1])
			bPort := make([]byte, 4)
			// http <=> socks5 完成后续握手
			buffer := bytes.NewBuffer(nil)
			buffer.Write([]byte{0x5, 0x1, 0x0, 0x3})
			buffer.WriteRune(rune(len(up[0])))
			buffer.Write([]byte(up[0]))
			binary.BigEndian.PutUint32(bPort, uint32(port))
			binary.Write(buffer, binary.BigEndian, &bPort)
			if _, err := nn.Write(buffer.Bytes()); err != nil {
				return nil, "", err
			}
			{
				var b [1024]byte
				n, err := nn.Read(b[:])
				if err != nil {
					return nil, "", err
				}
				if n != 10 {
					return nil, "", errors.New("socks5 connect error")
				}
				if b[0] != 0x5 && b[1] != 0x0 && b[2] != 0x0 && b[3] != 0x1 {
					return nil, "", errors.New("socks5 server connect error")
				}
			}

			if strings.HasPrefix(o.firstLine, "CONNECT") {
				if _, err := o.Client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return nil, "", err
				}
			} else {
				firstLine := strings.ReplaceAll(o.firstLine, uri.Scheme+"://"+uri.Host, "")
				if _, err := nn.Write([]byte(firstLine + header)); err != nil {
					return nil, "", err
				}
			}
			o.PI.OnSuccess(o.Client, nn)
			return nn, "", nil
		}

		if err == nil {
			o.PI.OnSuccess(o.Client, nn)
		}
		return nn, newHeader, err
	}

	return nil, header, nil
}

// HTTP二级代理
func (o *PProxy) httpLevel2(originHeader, authLine, newAuth string) (net.Conn, string, error) {
	u, err := url.Parse(newAuth)
	if err != nil {
		return nil, "", err
	}

	// replace proxy authorization
	newAuthLine := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String())) + "\r\n"
	newHeader := strings.ReplaceAll(originHeader, authLine, newAuthLine)

	if !strings.Contains(u.Host, ":") {
		u.Host += ":80"
	}
	// Dail
	newConn, err := net.Dial("tcp", u.Host)
	if err == nil {
		if _, err := newConn.Write([]byte(o.firstLine + newHeader)); err != nil {
			newConn.Close()
			return nil, "", err
		}
	}
	return newConn, "", err
}

// 二级代理
func (o *PProxy) level2(originHeader, authLine, newAuth string) (net.Conn, string, error) {
	if strings.HasPrefix(newAuth, "socks5") {
		n, err := o.socks5Level2(newAuth)
		return n, "", err
	} else if strings.HasPrefix(newAuth, "http") {
		return o.httpLevel2(originHeader, authLine, newAuth)
	} else {
		return nil, "", errors.New("unknown level2")
	}
}

// CopyHelper io.Copy helper
func CopyHelper(a, b net.Conn) {
	go func() {
		io.Copy(a, b)
		a.Close()
	}()
	io.Copy(b, a)
}

type sockIP struct {
	A, B, C, D byte
	PORT       uint16
}

func (ip sockIP) toAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", ip.A, ip.B, ip.C, ip.D, ip.PORT)
}
