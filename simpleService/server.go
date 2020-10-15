package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sort"
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

func (o *Server) webServer(webPort string) error {
	// curl 'http://127.0.0.1:8080/account/add?k=k&v=v'
	http.HandleFunc("/account/add", func(w http.ResponseWriter, r *http.Request) {
		k := r.FormValue("k")
		v := r.FormValue("v")

		if k == "" {
			outJSON(w, 1, "k is empty")
			return
		}
		accounts.Store(k, v)
		o.msg.SendToAll(cmdAccountAdd, 0, aesCrypt([]byte(k+"\x00"+v)))

		outJSON(w, 0, "ok")
	})

	// curl 'http://127.0.0.1:8080/account/adds' -d '{"k1":"v1","k2":"v2"}'
	http.HandleFunc("/account/adds", func(w http.ResponseWriter, r *http.Request) {
		bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			outJSON(w, 1, err.Error())
			return
		}
		defer r.Body.Close()

		fmt.Println(string(bs))

		m := map[string]string{}
		if err := json.Unmarshal(bs, &m); err != nil {
			outJSON(w, 1, err.Error())
			return
		}

		for k, v := range m {
			accounts.Store(k, v)
			o.msg.SendToAll(cmdAccountAdd, 0, aesCrypt([]byte(k+"\x00"+v)))
		}

		outJSON(w, 0, "ok")
	})

	// curl 'http://127.0.0.1:8080/account/del?k=k'
	http.HandleFunc("/account/del", func(w http.ResponseWriter, r *http.Request) {
		k := r.FormValue("k")

		if k == "" {
			outJSON(w, 1, "k is empty")
			return
		}
		accounts.Delete(k)
		o.msg.SendToAll(cmdAccountDel, 0, aesCrypt([]byte(k)))
		o.msg.SendToAll(cmdAccountDisconnect, 0, aesCrypt([]byte(k)))

		outJSON(w, 0, "ok")
	})

	// curl 'http://127.0.0.1:8080/account/list'
	http.HandleFunc("/account/list", func(w http.ResponseWriter, r *http.Request) {
		kv := []string{}
		accounts.Range(func(k, v interface{}) bool {
			kv = append(kv, k.(string)+"\x00"+v.(string))
			return true
		})
		sort.Strings(kv)

		outJSON(w, 0, kv)
	})

	// curl 'http://127.0.0.1:8080/account/disconnect?k=k'
	http.HandleFunc("/account/disconnect", func(w http.ResponseWriter, r *http.Request) {
		k := r.FormValue("k")

		if k == "" {
			outJSON(w, 1, "k is empty")
			return
		}

		o.msg.SendToAll(cmdAccountDisconnect, 0, aesCrypt([]byte(k)))

		outJSON(w, 0, "ok")
	})

	// curl 'http://127.0.0.1:8080/account/request?k=m:n'
	http.HandleFunc("/account/request", func(w http.ResponseWriter, r *http.Request) {
		lServer.Log0Debug("/account/request")
		outJSON(w, 0, "http://a:b@127.0.0.1:9999")
	})

	// curl 'http://127.0.0.1:8080/status'
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]interface{}{}

		{
			kv := []string{}
			accounts.Range(func(k, v interface{}) bool {
				kv = append(kv, k.(string)+"\x00"+v.(string))
				return true
			})
			sort.Strings(kv)
			out["accounts"] = kv
		}
		{
			kv := []string{}
			o.clients.Range(func(k, v interface{}) bool {
				kv = append(kv, k.(net.Conn).RemoteAddr().String())
				return true
			})
			sort.Strings(kv)
			out["clients"] = kv
		}

		outJSON(w, 0, out)
	})

	lServer.Log4Trace("listen:", webPort)
	return http.ListenAndServe(webPort, nil)
}
