package pproxy

import (
	"errors"
	"io"
	"net"
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

	DebugRead  func(conn net.Conn, bs []byte)
	DebugWrite func(conn net.Conn, bs []byte)
}

// Handshake ...
func (o *PProxy) Handshake() (conn net.Conn, err error) {
	// check socks5/http
	prefix := make([]byte, 1)
	if _, err = o.Client.Read(prefix); err != nil {
		return
	}

	switch prefix[0] {
	case 0x5:
		conn, err = o.handshakeSocks5(prefix)
	default:
		conn, err = o.handshakeHTTP(prefix)
	}

	return
}

// 二级代理
func (o *PProxy) level2(info *httpProxyInfo, newAuth string) (conn net.Conn, err error) {
	if strings.HasPrefix(newAuth, "socks5") {
		conn, err = o.socks5Level2(info, newAuth)
	} else if strings.HasPrefix(newAuth, "http") {
		conn, err = o.httpLevel2(info, newAuth)
	} else {
		return nil, errors.New("unknown level2")
	}

	return
}

// CopyHelper io.Copy helper
func CopyHelper(a, b net.Conn) {
	go func() {
		io.Copy(a, b)
		a.Close()
	}()
	io.Copy(b, a)
}
