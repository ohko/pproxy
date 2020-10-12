package httppproxy

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

// client <=> proxy1 <=> proxy2 <=> server

// proxy1 一级代理
type proxy1 struct{}

// OnAuth ...
func (o *proxy1) OnAuth(user, password string) (string, error) {
	log.Println("OnAuth1:", user, password)
	// 二级代理
	if user == "x1" && password == "y1" {
		return "http://x2:y2@127.0.0.1:8082", nil
	}
	// 直连
	if user == "x" && password == "y" {
		return "", nil
	}
	return "", errors.New("user:password check error")
}

// OnSuccess ...
func (o *proxy1) OnSuccess(clientConn net.Conn, serverConn net.Conn) {
	log.Println("OnSuccess1:", clientConn.RemoteAddr().String(), serverConn.RemoteAddr().String())
}

// proxy2 二级代理
type proxy2 struct{}

// OnAuth ...
func (o *proxy2) OnAuth(user, password string) (string, error) {
	log.Println("OnAuth2:", user, password)
	if user == "x2" && password == "y2" {
		return "", nil
	}
	return "", errors.New("user:password check error")
}

// OnSuccess ...
func (o *proxy2) OnSuccess(clientConn net.Conn, serverConn net.Conn) {
	log.Println("OnSuccess2:", clientConn.RemoteAddr().String(), serverConn.RemoteAddr().String())
}

// go test HTTPPProxy -run Test_HTTPPProxy -v -count=1
func Test_HTTPPProxy(t *testing.T) {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetFlags(log.Flags() | log.Lshortfile)

	// log.Println(hst.MakeTLSFile("123", "123", "123", "./", "127.0.0.1:8443", "ohko@qq.com"))

	go func() { // 启动服务器
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(r.RemoteAddr))
		})
		go http.ListenAndServe(":8080", nil)
		log.Println(http.ListenAndServeTLS(":8443", "ssl/ssl.crt", "ssl/ssl.key", nil))
	}()

	go func() { // 启动二级代理服务器
		s2, err := net.Listen("tcp", ":8082")
		if err != nil {
			log.Fatal(err)
		}

		for {
			conn, err := s2.Accept()
			if err != nil {
				log.Fatal(err)
			}

			go func(conn net.Conn) {
				defer conn.Close()

				newConn, err := (&HTTPPProxy{Client: conn, PI: &proxy2{}}).Handshake()
				if err != nil {
					log.Println(err)
					return
				}
				defer newConn.Close()

				CopyHelper(conn, newConn)
			}(conn)
		}
	}()

	go func() { // 启动一级代理服务器
		s1, err := net.Listen("tcp", ":8081")
		if err != nil {
			log.Fatal(err)
		}

		for {
			conn, err := s1.Accept()
			if err != nil {
				log.Fatal(err)
			}

			go func(conn net.Conn) {
				defer conn.Close()

				newConn, err := (&HTTPPProxy{Client: conn, PI: &proxy1{}}).Handshake()
				if err != nil {
					log.Println(err)
					return
				}
				defer newConn.Close()

				CopyHelper(conn, newConn)
			}(conn)
		}
	}()

	time.Sleep(time.Second)

	// 代理请求
	req := func(urlProxy *url.URL, url string) {
		transport := http.Transport{}
		transport.Proxy = http.ProxyURL(urlProxy)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

		client := &http.Client{}
		client.Transport = &transport
		resp, err := client.Get(url) // do request through proxy
		if err != nil {
			t.Fatal(err)
		}

		bs, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if !strings.HasPrefix(string(bs), "127.0.0.1:") {
			t.Fatal(string(bs))
		}
	}

	{ // 测试二级代理
		fmt.Println("测试二级代理")
		uri := url.URL{}
		urlProxy, _ := uri.Parse("http://x1:y1@127.0.0.1:8081")
		req(urlProxy, "http://127.0.0.1:8080")
	}

	{ // 测试直连
		fmt.Println("测试直连")
		uri := url.URL{}
		urlProxy, _ := uri.Parse("http://x:y@127.0.0.1:8081")
		req(urlProxy, "http://127.0.0.1:8080")
	}

	{ // 测试HTTPS
		fmt.Println("测试HTTPS")
		uri := url.URL{}
		urlProxy, _ := uri.Parse("http://x1:y1@127.0.0.1:8081")
		req(urlProxy, "https://127.0.0.1:8443")
	}
}
