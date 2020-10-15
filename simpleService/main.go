package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/ohko/logger"
)

// ...
const (
	cmdAccountList       = 1 // 1.账号列表 AccountList() => [u1=>u2]
	cmdAccountAdd        = 2 // 2.添加账号 AccountAdd(u1,u2)
	cmdAccountDel        = 3 // 3.删除账号 AccountDel(u1)
	cmdAccountDisconnect = 4 // 4.断开账号 AccountDisconnect(u1)
	cmdErrorMessage      = 5 // 5.错误消息
	bufferSize           = 1024 * 1024
)

var (
	serverPort    = flag.String("s", ":2399", "服务端口")
	proxyPort     = flag.String("l", ":8082", "代理端口")
	serverWebPort = flag.String("ss", ":8080", "服务器HTTP端口")
	clientWebPort = flag.String("cs", ":8081", "客户端HTTP端口")
	key           = flag.String("key", "20201015", "密钥，留空不启用AES加密")
	crc           = flag.Bool("crc", false, "是否启动crc校验数据")

	aesEnable bool
	aesKey    [32]byte
	aesIV     [16]byte
	lServer   = logger.NewLogger(nil)
	lClient   = logger.NewLogger(nil)
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetFlags(log.Flags() | log.Lshortfile)

	if (*serverPort)[0] == ':' {
		o := &Server{}
		if err := o.Start(*key, *serverPort, *serverWebPort, *crc); err != nil {
			log.Fatal(err)
		}
	} else if *serverPort != "" {
		o := &Client{}
		if err := o.Start(*key, *serverPort, *proxyPort, *clientWebPort, *crc); err != nil {
			log.Fatal(err)
		}
	}

	WaitCtrlC()
}

// WaitCtrlC 捕捉Ctrl+C
func WaitCtrlC() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}

func outJSON(w http.ResponseWriter, no int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	m := &msg{No: no, Data: data}
	bs, _ := m.Encode()
	w.Write(bs)
}

// Request 获取http/https内容
func Request(method, url, cookie, data string, header map[string]string) ([]byte, []*http.Cookie, error) {
	var client *http.Client

	if strings.HasPrefix(url, "https://") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}

	req, err := http.NewRequest(method, url, strings.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Cookie", cookie)
	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	return bs, res.Cookies(), nil
}

func aesCrypt(data []byte) []byte {
	if !aesEnable {
		return data
	}
	block, _ := aes.NewCipher(aesKey[:])
	buf := make([]byte, len(data))

	stream := cipher.NewCTR(block, aesIV[:])
	stream.XORKeyStream(buf, data)
	return buf
}

type msg struct {
	No   int
	Data interface{}
}

func (o *msg) Encode() ([]byte, error) {
	return json.Marshal(o)
}
func (o *msg) Decode(bs []byte) error {
	return json.Unmarshal(bs, o)
}
