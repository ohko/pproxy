package main

import (
	"crypto/md5"
	"crypto/sha256"
	"io"
	"log"
	"net"
	"sync"

	"github.com/ohko/omsg"
)

var (
	accounts sync.Map
)

// Server 服务端
type Server struct {
	msg        *omsg.Server
	serverPort string
	clients    sync.Map
}

// Start 启动服务
func (o *Server) Start(key, serverPort, webPort string, crc bool) (err error) {
	lServer.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)
	lServer.SetPrefix("S")
	lServer.SetColor(true)
	o.serverPort = serverPort

	accounts.Store("a:b", "")                          // 直连
	accounts.Store("x:y", "http://a:b@127.0.0.1:9999") // 二级代理
	accounts.Store("m:n",
		"request:http://127.0.0.1:8080/account/request?k=m:n") // 反向请求代理设置

	go o.webServer(webPort)

	// setup AES
	if len(key) > 0 {
		aesEnable = true
		aesKey = sha256.Sum256([]byte(key))
		aesIV = md5.Sum([]byte(key))
		lServer.Log4Trace("AES crypt enabled")
	} else {
		lServer.Log4Trace("AES crypt disabled")
	}

	if o.msg, err = omsg.Listen("tcp", o.serverPort); err != nil {
		return
	}
	go func() {
		lServer.Log4Trace("server:", o.serverPort)
		lServer.Log4Trace(o.msg.Run(o, crc))
	}()

	return
}

// OnRecvError ...
func (o *Server) OnRecvError(conn net.Conn, err error) {
	if err != io.EOF {
		lServer.Log2Error(err)
	}
}

// OnAccept ...
func (o *Server) OnAccept(conn net.Conn) bool {
	lServer.Log0Debug("client connect:", conn.RemoteAddr())

	defer func(conn net.Conn) { // 发送账号
		accounts.Range(func(k, v interface{}) bool {
			if err := o.Send(conn, cmdAccountAdd, 0, []byte(k.(string)+"\x00"+v.(string))); err != nil {
				lServer.Log2Error("send account error:", conn.RemoteAddr(), err)
				return false
			}
			return true
		})
	}(conn)

	o.clients.Store(conn, nil)
	return true
}

// OnClientClose ...
func (o *Server) OnClientClose(conn net.Conn) {
	o.clients.Delete(conn)
	lServer.Log0Debug("client close:", conn.RemoteAddr())
}

// OnData ...
func (o *Server) OnData(conn net.Conn, cmd, ext uint16, data []byte) error {
	data = aesCrypt(data)
	// lServer.Log0Debug(fmt.Sprintf("0x%x-0x%x:\n%s", cmd, ext, hex.Dump(data)))

	switch cmd {
	case cmdErrorMessage:
		lServer.Log2Error(conn.RemoteAddr(), string(data))
	}

	return nil
}

// Send 原始数据加密后发送
func (o *Server) Send(conn net.Conn, cmd, ext uint16, originData []byte) error {
	return o.msg.Send(conn, cmd, ext, aesCrypt(originData))
}
