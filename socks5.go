package pproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// hand socks5 proxy
func (o *PProxy) handshakeSocks5(prefix []byte) (conn net.Conn, err error) {
	b := make([]byte, 0x100)
	rlen := 0

	// 客户端:请求代理设置
	// 05 01 00 共3字节，这种是要求匿名代理
	// 05 01 02 共3字节，这种是要求以用户名密码方式验证代理
	// 05 02 00 02 共4字节，这种是要求以匿名或者用户名密码方式代理
	_, err = io.ReadFull(o.Client, b[:1])
	if err != nil {
		return
	}
	if b[0] == 0 || b[0] >= 0xff {
		return nil, errors.New("accept error")
	}
	rlen = int(b[0])
	if _, err = io.ReadFull(o.Client, b[:rlen]); err != nil {
		return
	}

	// 服务端:如果socks5代理允许匿名那么就返回05 00两个字节，如果要求验证就返回05 02两个字节。
	if _, err = o.Client.Write([]byte{0x05, 0x02}); err != nil {
		return
	}

	// 当上面socks5返回05 02两个字节后
	// 客户端发送01 06 6C 61 6F  74 73 65 06 36 36 36 38 38 38
	// 1、01固定的
	// 2、06这一个字节这是指明用户名长度，说明后面紧跟的6个字节就是用户名
	// 3、6C 61 6F 74 73 65这就是那6个是用户名，是laotse的ascii
	// 4、又一个06共1个字节指明密码长度，说明后面紧跟的6个字节就是密码
	// 5、36 36 36 38 38 38就是这6个是密码，666888的ascii。
	// 6、假如这后面还有字节，一律无视。
	if _, err = io.ReadFull(o.Client, b[:2]); err != nil {
		return
	}
	if b[0] != 0x1 {
		return nil, errors.New("need user and password")
	}
	// user
	rlen = int(b[1])
	if _, err = io.ReadFull(o.Client, b[:rlen]); err != nil {
		return
	}
	user := string(b[:rlen])
	// password
	if _, err = io.ReadFull(o.Client, b[:1]); err != nil {
		return
	}
	rlen = int(b[0])
	if _, err = io.ReadFull(o.Client, b[:rlen]); err != nil {
		return
	}
	password := string(b[:rlen])

	// 服务器验证失败，直接关闭连接即可
	// 服务器验证成功后，就发送01 00给客户端，后面和匿名代理一样了
	var newAuth string
	newAuth, err = o.PI.OnAuth(user, password)
	if err != nil {
		return
	}
	o.Client.Write([]byte{0x01, 0x00})

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
	if _, err = o.Client.Read(b[:4]); err != nil {
		return
	}
	if b[0] != 0x5 {
		return nil, errors.New("proxy command error")
	}

	var addr string
	switch b[3] {
	case 0x01: // IP模式
		sip := sockIP{}
		if err = binary.Read(o.Client, binary.BigEndian, &sip); err != nil {
			return
		}
		addr = sip.toAddr()
		// log.Printf("IP代理模式: %s", addr)
	case 0x03: // 域名模式
		if _, err = io.ReadFull(o.Client, b[:1]); err != nil {
			return
		}
		rlen = int(b[0])
		if rlen > 0x80 {
			return nil, errors.New("host too long")
		}
		if _, err = io.ReadFull(o.Client, b[:rlen]); err != nil {
			return
		}
		host := string(b[:rlen])
		var port uint16
		if err = binary.Read(o.Client, binary.BigEndian, &port); err != nil {
			return
		}
		addr = fmt.Sprintf("%s:%d", host, port)
		// log.Printf("域名要求代理: %s", addr)
	default: // 未知模式
		return nil, fmt.Errorf("未知模式")
	}

	// 二级代理
	if newAuth != "" {
		info := &httpProxyInfo{uri: addr}

		if strings.HasPrefix(newAuth, "http") {
			info.originHeader = "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\nProxy-Authorization: Basic eDp5\r\nUser-Agengt: pproxy\r\n\r\n"
			info.authLine = "Proxy-Authorization: Basic eDp5\r\n"
			info.method = "CONNECT"
		}

		if conn, err = o.level2(info, newAuth); err != nil {
			return
		}
	}

	// 建立连接
	if conn, err = net.Dial("tcp", addr); err != nil {
		return
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()

	// 返回成功建立代理: 05 00 00 01 C0 A8  00 08 16 CE共10个字节
	// 1、05 00 00 01固定的
	// 2、后面8个字节可以全是00，也可以发送socks5服务器连接远程主机用到的ip地址和端口，比如这里C0 A8 00 08，就是192.168.0.8，16 CE即5838端口，即是socks5服务器用5838端口去连接百度的80端口。
	if _, err = o.Client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return
	}

	o.PI.OnSuccess(o.Client, conn)
	return
}

// socks5二级代理
func (o *PProxy) socks5Level2(info *httpProxyInfo, newAuth string) (conn net.Conn, err error) {
	info.level2 = "socks5"

	b := make([]byte, 0x100)
	var u *url.URL

	// log.Println("二级代理:", newAuth)
	if u, err = url.Parse(newAuth); err != nil {
		return
	}

	// Dail
	if conn, err = net.Dial("tcp", u.Host); err != nil {
		return
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()

	// 匿名/登录
	if _, err = conn.Write([]byte{0x5, 0x2, 0x0, 0x2}); err != nil {
		return
	}
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return
	}
	if b[0] != 0x5 {
		return nil, errors.New("proxy command error")
	}
	if b[1] != 0x0 && b[1] != 2 {
		return nil, errors.New("login return unknown command")
	}

	// need login
	if b[1] == 0x2 {
		b = b[:0]
		b = append(b, 0x1)
		b = append(b, byte(len(u.User.Username())))
		b = append(b, []byte(u.User.Username())...)
		p, _ := u.User.Password()
		b = append(b, byte(len(p)))
		b = append(b, []byte(p)...)
		if _, err = conn.Write(b); err != nil {
			return
		}

		if _, err = io.ReadFull(conn, b[:2]); err != nil {
			return
		}
		if b[0] != 0x1 && b[1] != 0 {
			return nil, errors.New("socks5 login error")
		}
	}

	// 域名方式代理
	port := 0
	up := strings.Split(info.uri, ":")
	if port, err = strconv.Atoi(up[1]); err != nil {
		return
	}
	b = b[:0]
	b = append(b, []byte{0x5, 0x1, 0x0, 0x3}...)
	b = append(b, byte(len(up[0])))
	b = append(b, []byte(up[0])...)
	bPort := make([]byte, 2)
	binary.BigEndian.PutUint16(bPort, uint16(port))
	b = append(b, bPort...)
	if _, err = conn.Write(b); err != nil {
		return
	}
	if _, err = io.ReadFull(conn, b[:10]); err != nil {
		return
	}
	if b[0] != 0x5 && b[1] != 0x0 && b[2] != 0x0 && b[3] != 0x1 {
		return nil, errors.New("socks5 server connect error")
	}

	return
}

type sockIP struct {
	A, B, C, D byte
	PORT       uint16
}

func (ip sockIP) toAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", ip.A, ip.B, ip.C, ip.D, ip.PORT)
}
