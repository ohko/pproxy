package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"pproxy"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohko/omsg"
)

var (
	accountCache sync.Map // 账号 u1:p1 => u2:p2
	requestCache sync.Map // 动态账号 u1:p1 => u2:p2
	userConns    sync.Map // 代理客服端连接 u => conn
	level2Conns  sync.Map // 代理客户=>二级代理 conn=>level2
)

// Client 客户端
type Client struct {
	msg               *omsg.Client
	serverPort        string
	proxyPort         string
	clientWebPort     string
	crc               bool
	localServers      sync.Map // map[浏览器IP:Port + 本地服务IP:Port]本地服务连接
	localServersCount int64    // 连接数
}

// Start 启动客户端
func (o *Client) Start(key, serverPort, proxyPort, clientWebPort string, crc bool) (err error) {
	lClient.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)
	lClient.SetPrefix("C")
	lClient.SetColor(true)
	o.serverPort, o.proxyPort, o.clientWebPort, o.crc = serverPort, proxyPort, clientWebPort, crc

	// setup AES
	if len(key) > 0 {
		aesEnable = true
		aesKey = sha256.Sum256([]byte(key))
		aesIV = md5.Sum([]byte(key))
		lClient.Log4Trace("AES crypt enabled")
	} else {
		lClient.Log4Trace("AES crypt disabled")
	}

	go o.Listen()
	go o.webServer(o.clientWebPort)
	go o.ForTestLevel2()

	return o.Reconnect()
}

// OnRecvError ...
func (o *Client) OnRecvError(err error) {
	if err != io.EOF {
		lClient.Log2Error(err)
	}
}

// OnClose ...
func (o *Client) OnClose() {
	lClient.Log0Debug("connect closed:", o.serverPort)

	// 清理本地数据
	o.localServers.Range(func(key, val interface{}) bool {
		val.(net.Conn).Close()
		o.localServers.Delete(key)
		atomic.AddInt64(&o.localServersCount, -1)
		return true
	})

	// 断线后重连
	o.Reconnect()
}

// OnData ...
func (o *Client) OnData(cmd, ext uint16, data []byte) error {
	data = aesCrypt(data)
	// lClient.Log0Debug(fmt.Sprintf("0x%x-0x%x:\n%s", cmd, ext, hex.Dump(data)))

	switch cmd {
	case cmdAccountList:
		kv := []string{}
		accountCache.Range(func(k, v interface{}) bool {
			kv = append(kv, k.(string)+"\x00"+v.(string))
			return true
		})
		sort.Strings(kv)

		bs, _ := json.Marshal(kv)
		o.Send(cmdAccountList, 0, aesCrypt(bs))
	case cmdAccountAdd:
		tmp := strings.Split(string(data), "\x00")
		if len(tmp) != 2 {
			lClient.Log2Error("account add error:" + string(data))
			break
		}
		lClient.Log0Debug("account add:", tmp[0], tmp[1])
		accountCache.Store(tmp[0], tmp[1])
	case cmdAccountDel:
		lClient.Log0Debug("account del:", string(data))
		accountCache.Delete(string(data))
		requestCache.Delete(string(data))
	case cmdAccountDisconnect:
		lClient.Log0Debug("account disconnect:", string(data))
		userConns.Range(func(k, v interface{}) bool {
			if k == string(data) {
				v.(net.Conn).Close()
				userConns.Delete(k)
				return false
			}
			return true
		})
	}

	return nil
}

// Send 原始数据加密后发送
func (o *Client) Send(cmd, ext uint16, originData []byte) error {
	return o.msg.Send(cmd, ext, aesCrypt(originData))
}

// Reconnect 重新连接服务器
func (o *Client) Reconnect() (err error) {
	// 等待1秒再重连
	time.Sleep(time.Second)

	for {
		if o.msg, err = omsg.DialTimeout("tcp", o.serverPort, time.Second*3, o, o.crc); err != nil {
			lClient.Log2Error(err)
			time.Sleep(time.Second)
			continue
		}

		break
	}
	lClient.Log0Debug("connect success:", o.serverPort)

	return nil
}

// Listen ...
func (o *Client) Listen() error {
	lClient.Log4Trace("listen:", o.proxyPort)
	s1, err := net.Listen("tcp", o.proxyPort)
	if err != nil {
		return err
	}

	for {
		conn, err := s1.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			defer conn.Close()
			defer o.OnClientClose(conn)

			pp1 := &pproxy.PProxy{Client: conn, PI: o}
			// pp1.DebugRead = o.DebugRead
			// pp1.DebugWrite = o.DebugWrite

			newConn, err := pp1.Handshake()
			if err != nil {
				lClient.Log2Error(err)
				return
			}
			defer newConn.Close()
			defer o.OnServerClose(newConn)

			pproxy.CopyHelper(conn, newConn)
		}(conn)
	}
}

// OnAuth ...
func (o *Client) OnAuth(conn net.Conn, user, password string) (level2 string, err error) {
	lClient.Log0Debug("proxy:", user, password)
	k := user + ":" + password
	var (
		l2 interface{}
		ok bool
	)

	// 先查动态账号缓存是否存在
	if l2, ok = requestCache.Load(k); ok {
		level2 = l2.(string)
		userConns.Store(k, conn)
		return
	}

	// 再查账号是否存在
	if l2, ok = accountCache.Load(k); ok {
		level2 = l2.(string)

		if strings.HasPrefix(level2, "request:") {
			var bs []byte
			if bs, _, err = Request("GET", level2[len("request:"):], "", "", nil); err != nil {
				return
			}
			m := &msg{}
			if err = m.Decode(bs); err != nil {
				return
			}
			if m.No != 0 {
				return "", errors.New(m.Data.(string))
			}
			requestCache.Store(k, m.Data.(string))
			level2 = m.Data.(string)
		}

		userConns.Store(k, conn)
		return
	}

	return "", errors.New("user:password check error")
}

// OnSuccess ...
func (o *Client) OnSuccess(clientConn net.Conn, serverConn net.Conn) {
	level2Conns.Store(clientConn, serverConn)
	lClient.Log0Debug("OnSuccess:", clientConn.RemoteAddr().String(), serverConn.RemoteAddr().String())
}

// DebugRead ...
func (o *Client) DebugRead(conn net.Conn, bs []byte) {
	log.Output(2, fmt.Sprintln("DebugRead:", conn, "\n"+hex.Dump(bs)))
}

// DebugWrite ...
func (o *Client) DebugWrite(conn net.Conn, bs []byte) {
	log.Output(2, fmt.Sprintln("DebugWrite:", conn, "\n"+hex.Dump(bs)))
}

// OnClientClose ...
func (o *Client) OnClientClose(conn net.Conn) {
	lClient.Log0Debug("OnClientClose:", conn.RemoteAddr().String())
	level2Conns.Delete(conn)
	userConns.Range(func(k, v interface{}) bool {
		if v == conn {
			userConns.Delete(k)
			return false
		}
		return true
	})
}

// OnServerClose ...
func (o *Client) OnServerClose(conn net.Conn) {
	lClient.Log0Debug("OnServerClose:", conn.RemoteAddr().String())
	level2Conns.Range(func(k, v interface{}) bool {
		if v == conn {
			level2Conns.Delete(k)
			return false
		}
		return true
	})
}
