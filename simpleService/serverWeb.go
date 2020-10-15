package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
)

func (o *Server) webServer(webPort string) error {
	http.HandleFunc("/account/add", o.webAccountAdd)
	http.HandleFunc("/account/adds", o.webAccountAdds)
	http.HandleFunc("/account/del", o.webAccountDel)
	http.HandleFunc("/account/list", o.webAccountList)
	http.HandleFunc("/account/disconnect", o.webAccountDisconnect)
	http.HandleFunc("/account/request", o.webAccountRequest)
	http.HandleFunc("/status", o.webStatus)

	lServer.Log4Trace("listen:", webPort)
	return http.ListenAndServe(webPort, nil)
}

// curl 'http://127.0.0.1:8080/account/add?k=k&v=v'
func (o *Server) webAccountAdd(w http.ResponseWriter, r *http.Request) {
	k := r.FormValue("k")
	v := r.FormValue("v")

	if k == "" {
		outJSON(w, 1, "k is empty")
		return
	}
	accounts.Store(k, v)
	o.msg.SendToAll(cmdAccountAdd, 0, aesCrypt([]byte(k+"\x00"+v)))

	outJSON(w, 0, "ok")
}

// curl 'http://127.0.0.1:8080/account/adds' -d '{"k1":"v1","k2":"v2"}'
func (o *Server) webAccountAdds(w http.ResponseWriter, r *http.Request) {
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
}

// curl 'http://127.0.0.1:8080/account/del?k=k'
func (o *Server) webAccountDel(w http.ResponseWriter, r *http.Request) {
	k := r.FormValue("k")

	if k == "" {
		outJSON(w, 1, "k is empty")
		return
	}
	accounts.Delete(k)
	o.msg.SendToAll(cmdAccountDel, 0, aesCrypt([]byte(k)))
	o.msg.SendToAll(cmdAccountDisconnect, 0, aesCrypt([]byte(k)))

	outJSON(w, 0, "ok")
}

// curl 'http://127.0.0.1:8080/account/list'
func (o *Server) webAccountList(w http.ResponseWriter, r *http.Request) {
	kv := []string{}
	accounts.Range(func(k, v interface{}) bool {
		kv = append(kv, k.(string)+"\x00"+v.(string))
		return true
	})
	sort.Strings(kv)

	outJSON(w, 0, kv)
}

// curl 'http://127.0.0.1:8080/account/disconnect?k=k'
func (o *Server) webAccountDisconnect(w http.ResponseWriter, r *http.Request) {
	k := r.FormValue("k")

	if k == "" {
		outJSON(w, 1, "k is empty")
		return
	}

	o.msg.SendToAll(cmdAccountDisconnect, 0, aesCrypt([]byte(k)))

	outJSON(w, 0, "ok")
}

// curl 'http://127.0.0.1:8080/account/request?k=m:n'
func (o *Server) webAccountRequest(w http.ResponseWriter, r *http.Request) {
	lServer.Log0Debug("/account/request")
	outJSON(w, 0, "http://a:b@127.0.0.1:9999")
}

// curl 'http://127.0.0.1:8080/status'
func (o *Server) webStatus(w http.ResponseWriter, r *http.Request) {
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
}
