package main

import (
	"net"
	"net/http"
	"sort"
)

func (o *Client) webServer(webPort string) error {
	http.HandleFunc("/status", o.webStatus)

	lClient.Log4Trace("listen:", webPort)
	return http.ListenAndServe(webPort, nil)
}

// curl 'http://127.0.0.1:8081/status'
func (o *Client) webStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{}

	{
		kv := []string{}
		accountCache.Range(func(k, v interface{}) bool {
			kv = append(kv, k.(string)+"\x00"+v.(string))
			return true
		})
		sort.Strings(kv)
		out["accountCache"] = kv
	}
	{
		kv := []string{}
		userConns.Range(func(k, v interface{}) bool {
			kv = append(kv, k.(string)+"=>"+v.(net.Conn).RemoteAddr().String())
			return true
		})
		sort.Strings(kv)
		out["userConns"] = kv
	}
	{
		kv := []string{}
		level2Conns.Range(func(k, v interface{}) bool {
			kv = append(kv, k.(net.Conn).RemoteAddr().String()+"=>"+v.(net.Conn).RemoteAddr().String())
			return true
		})
		sort.Strings(kv)
		out["level2Conns"] = kv
	}

	outJSON(w, 0, out)
}
