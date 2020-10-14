package pproxy

import (
	"crypto/rand"
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

	"golang.org/x/net/proxy"
)

// client <=> proxy1[socks5/http] <=> proxy2[socks5/http] <=> ... <=> server

var sumChk = 0

// proxy1 一级代理
type proxy1 struct{}

// OnAuth ...
func (o *proxy1) OnAuth(user, password string) (string, error) {
	sumChk |= 1
	log.Output(2, fmt.Sprintln("OnAuth1:", user, password))
	// 二级HTTP代理
	if user == "hh1" && password == "hh1" {
		return "http://h2:h2@127.0.0.1:8082", nil
	}
	// 二级Socks5代理
	if user == "ss1" && password == "ss1" {
		return "socks5://s2:s2@127.0.0.1:8082", nil
	}
	// 二级HTTP<=>Socks5代理
	if user == "hs1" && password == "hs1" {
		return "socks5://s2:s2@127.0.0.1:8082", nil
	}
	// 二级Socks5<=>HTTP代理
	if user == "sh1" && password == "sh1" {
		return "http://h2:h2@127.0.0.1:8082", nil
	}
	// 直连
	if user == "x" && password == "y" {
		return "", nil
	}
	return "", errors.New("user:password check error")
}

// OnSuccess ...
func (o *proxy1) OnSuccess(clientConn net.Conn, serverConn net.Conn) {
	sumChk |= 2
	log.Output(2, fmt.Sprintln("OnSuccess1:", clientConn.RemoteAddr().String(), serverConn.RemoteAddr().String()))
}

// proxy2 二级代理
type proxy2 struct{}

// OnAuth ...
func (o *proxy2) OnAuth(user, password string) (string, error) {
	sumChk |= 4
	log.Output(2, fmt.Sprintln("OnAuth2:", user, password))
	if user == "h2" && password == "h2" {
		return "", nil
	}
	if user == "s2" && password == "s2" {
		return "", nil
	}
	return "", errors.New("user:password check error")
}

// OnSuccess ...
func (o *proxy2) OnSuccess(clientConn net.Conn, serverConn net.Conn) {
	sumChk |= 8
	log.Output(2, fmt.Sprintln("OnSuccess2:", clientConn.RemoteAddr().String(), serverConn.RemoteAddr().String()))
}

// go test pproxy -run Test_PPProxy -v -count=1
func Test_PPProxy(t *testing.T) {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetFlags(log.Flags() | log.Lshortfile)

	go func() { // 启动服务器
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			w.Write([]byte(r.FormValue("a") + "_" + r.FormValue("b") + "_" + r.RemoteAddr))
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

				newConn, err := (&PProxy{Client: conn, PI: &proxy2{}}).Handshake()
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

				newConn, err := (&PProxy{Client: conn, PI: &proxy1{}}).Handshake()
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
	// <-make(chan bool, 1)

	// 代理请求
	req := func(chk int, proxyURL, navURL string) {
		sumChk = 0
		t.Log(proxyURL, navURL)
		urlProxy, _ := (&url.URL{}).Parse(proxyURL)
		var transport *http.Transport
		if urlProxy.Scheme == "http" {
			// t.Log("use http")
			transport = &http.Transport{}
			transport.Proxy = http.ProxyURL(urlProxy)
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else if urlProxy.Scheme == "socks5" {
			// t.Log("use socks5")
			auth := proxy.Auth{}
			auth.User = urlProxy.User.Username()
			auth.Password, _ = urlProxy.User.Password()
			dialer, err := proxy.SOCKS5("tcp", urlProxy.Host, &auth, proxy.Direct)
			if err != nil {
				t.Fatal("can't connect to the proxy:", err)
			}
			transport = &http.Transport{Dial: dialer.Dial}
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			t.Fatal("unknown proxy proto")
		}

		client := &http.Client{Transport: transport}
		a, b := makeGUID(), makeGUID()
		resp, err := client.Post(navURL+"?a="+a,
			"application/x-www-form-urlencoded",
			strings.NewReader("b="+b))
		if err != nil {
			t.Fatal(err)
		}

		bs, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if !strings.HasPrefix(string(bs), a+"_"+b+"_127.0.0.1:") {
			t.Fatal(string(bs))
		}

		if chk != sumChk {
			t.Fatalf("chk error: want:%d give:%d", chk, sumChk)
		}
	}

	{ // 测试二级代理 http <=> http
		t.Log("=== 测试二级代理 http <=> http ===")
		req(1|2|4|8, "http://hh1:hh1@127.0.0.1:8081", "http://127.0.0.1:8080")
		req(1|2|4|8, "http://hh1:hh1@127.0.0.1:8081", "https://127.0.0.1:8443")
	}

	{ // 测试二级代理 socks5 <=> socks5
		t.Log("=== 测试二级代理 socks5 <=> socks5 ===")
		req(1|2|4|8, "socks5://ss1:ss1@127.0.0.1:8081", "http://127.0.0.1:8080")
		req(1|2|4|8, "socks5://ss1:ss1@127.0.0.1:8081", "https://127.0.0.1:8443")
	}

	{ // 测试二级代理 http <=> socks5
		t.Log("=== 测试二级代理 http <=> socks5 ===")
		req(1|2|4|8, "http://hs1:hs1@127.0.0.1:8081", "http://127.0.0.1:8080")
		req(1|2|4|8, "http://hs1:hs1@127.0.0.1:8081", "https://127.0.0.1:8443")
	}

	{ // 测试二级代理 socks5 <=> http
		t.Log("=== 测试二级代理 socks5 <=> http ===")
		req(1|2|4|8, "socks5://sh1:sh1@127.0.0.1:8081", "http://127.0.0.1:8080")
		req(1|2|4|8, "socks5://sh1:sh1@127.0.0.1:8081", "https://127.0.0.1:8443")
	}

	{ // 测试直连HTTP
		t.Log("=== 测试直连HTTP ===")
		req(1|2, "http://x:y@127.0.0.1:8081", "http://127.0.0.1:8080")
		req(1|2, "http://x:y@127.0.0.1:8081", "https://127.0.0.1:8443")
	}

	{ // 测试直连Socks5
		t.Log("=== 测试直连Socks5 ===")
		req(4|8, "http://h2:h2@127.0.0.1:8082", "http://127.0.0.1:8080")
		req(4|8, "socks5://s2:s2@127.0.0.1:8082", "https://127.0.0.1:8443")
	}
}

// makeGUID make GUID
// "crypto/rand"
func makeGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[8:10], b[6:8], b[4:6], b[10:])
}
