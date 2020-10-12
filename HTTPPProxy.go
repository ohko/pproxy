package httppproxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
)

// ProxyInterface ...
type ProxyInterface interface {
	// OnAuth 账号验证，返回error判断是否有错误，返回string为二级代理地址
	OnAuth(user, password string) (string, error)
	// OnSuccess 代理建立成功，返回客户端、代理端连接
	OnSuccess(clientConn net.Conn, serverConn net.Conn)
}

// HTTPPProxy 中继HTTP代理
type HTTPPProxy struct {
	Client net.Conn
	PI     ProxyInterface

	reader    *bufio.Reader
	firstLine string
}

// Handshake ...
func (o *HTTPPProxy) Handshake() (net.Conn, error) {
	// read first line
	o.reader = bufio.NewReader(o.Client)
	l, err := o.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	o.firstLine = l
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
func (o *HTTPPProxy) typeConnect(firstLineArr []string) (net.Conn, error) {
	// auth
	newConn, _, err := o.checkAuth()
	if err != nil {
		return nil, err
	}

	// p-proxy
	if newConn != nil {
		o.PI.OnSuccess(o.Client, newConn)
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
func (o *HTTPPProxy) typeOther(firstLineArr []string) (net.Conn, error) {
	u, err := url.Parse(firstLineArr[1])
	if err != nil {
		return nil, err
	}
	if !strings.Contains(u.Host, ":") {
		u.Host += ":80"
	}

	// auth
	newConn, header, err := o.checkAuth()
	if err != nil {
		return nil, err
	}

	// p-proxy
	if newConn != nil {
		o.PI.OnSuccess(o.Client, newConn)
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
func (o *HTTPPProxy) checkAuth() (net.Conn, string, error) {
	originHeader := ""
	header := ""
	authLine := ""
	for {
		l, err := o.reader.ReadString('\n')
		if err != nil {
			return nil, "", err
		}
		originHeader += l

		// Proxy-Connection: Keep-Alive
		if strings.HasPrefix(l, "Proxy-Connection") {
			continue
		}

		// Proxy-Authorization: Basic eDp5
		if strings.HasPrefix(l, "Proxy-Authorization") {
			authLine = l
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

	if newAuth != "" {
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

	return nil, header, nil
}

// CopyHelper io.Copy helper
func CopyHelper(a, b net.Conn) {
	go func() {
		io.Copy(a, b)
		a.Close()
	}()
	io.Copy(b, a)
}
