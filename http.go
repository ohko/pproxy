package pproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type httpProxyInfo struct {
	originHeader string // origin header map
	activeHeader string // header map
	firstLine    string // CONNECT http://127.0.0.1:8080/ HTTP/1.1
	authLine     string // Proxy-Authorization: Basic eDp5
	method       string // CONNECT/GET/POST/...
	connectTo    string // http://127.0.0.1:8080/
	uri          string // 127.0.0.1:8080
	host         string // 127.0.0.1
	port         int    // 8080

	level2 string // [empty|http|socks5]
}

// hand http proxy
func (o *PProxy) handshakeHTTP(prefix []byte) (conn net.Conn, err error) {

	// read to \r\n\r\n
	buffer := make([]byte, 0, 0x100)
	buffer = append(buffer, prefix...)
	b := make([]byte, 1)
	for {
		if _, err = o.Client.Read(b); err != nil {
			return
		}
		buffer = append(buffer, b...)
		if b[0] == '\n' && len(buffer) > 4 {
			if bytes.HasSuffix(buffer, []byte("\r\n\r\n")) {
				break
			}
		}
	}

	// read first line
	reader := bufio.NewReader(strings.NewReader(string(buffer)))
	line := ""
	if line, err = reader.ReadString('\n'); err != nil {
		return
	}
	// analyse Mehtod
	arrFirstLine := strings.Split(line, " ")

	info := httpProxyInfo{
		originHeader: line,
		activeHeader: line,
		firstLine:    line,
		method:       arrFirstLine[0],
		connectTo:    arrFirstLine[1],
		uri:          "",
		host:         "",
		port:         0,
	}

	if info.method != "CONNECT" {
		info.connectTo = strings.Join(strings.Split(info.connectTo, "/")[:3], "/") + "/"
	}

	// other header
	for {
		if line, err = reader.ReadString('\n'); err != nil {
			return
		}
		info.originHeader += line

		// Proxy-Authorization: Basic eDp5
		if strings.HasPrefix(line, "Proxy-Authorization") {
			info.authLine = line
			continue
		}

		// Proxy-Connection: Keep-Alive
		if strings.HasPrefix(line, "Proxy-") {
			continue
		}

		// Host: 127.0.0.1:8080
		if strings.HasPrefix(line, "Host: ") {
			info.uri = strings.TrimSpace(line[6:])
			if !strings.Contains(info.uri, ":") {
				info.uri += ":80"
			}
			uriArr := strings.Split(info.uri, ":")
			info.host = uriArr[0]
			if info.port, err = strconv.Atoi(uriArr[1]); err != nil {
				return
			}
		}

		info.activeHeader += line

		// end
		if len(strings.TrimSpace(line)) == 0 {
			break
		}
	}

	// auth
	if conn, err = o.checkAuth(&info); err != nil {
		return
	}

	// Dail
	if conn == nil {
		if conn, err = net.Dial("tcp", info.uri); err != nil {
			return
		}
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()

	if info.method == "CONNECT" {
		if _, err = o.Client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
	} else if info.level2 != "http" {
		if _, err = conn.Write([]byte(strings.ReplaceAll(info.activeHeader, info.connectTo, "/"))); err != nil {
			return
		}
	}

	o.PI.OnSuccess(o.Client, conn)
	return
}

// return newConn, header, error
func (o *PProxy) checkAuth(info *httpProxyInfo) (conn net.Conn, err error) {
	// analy user and password
	user, password := "", ""
	if info.authLine != "" {
		if strings.Contains(info.authLine, " Basic ") {
			var up []byte
			tmp := strings.Split(info.authLine, " ")
			if up, err = base64.StdEncoding.DecodeString(tmp[2]); err != nil {
				return
			}
			upArr := strings.Split(string(up), ":")
			if len(upArr) != 2 {
				return nil, errors.New("user:password error:" + string(up))
			}
			user, password = upArr[0], upArr[1]
		}
	}

	// callback auth and get new proxy setting if need
	var newAuth string
	if newAuth, err = o.PI.OnAuth(user, password); err != nil {
		return
	}

	// 二级代理
	if newAuth != "" {
		if conn, err = o.level2(info, newAuth); err != nil {
			return
		}

		if info.level2 == "socks5" && info.method == "CONNECT" {
			if _, err = o.Client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
		}
	}

	return
}

// HTTP二级代理
func (o *PProxy) httpLevel2(info *httpProxyInfo, newAuth string) (conn net.Conn, err error) {
	info.level2 = "http"

	var u *url.URL
	if u, err = url.Parse(newAuth); err != nil {
		return
	}

	// replace proxy authorization
	newAuthLine := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String())) + "\r\n"

	if !strings.Contains(u.Host, ":") {
		u.Host += ":80"
	}

	// Dail
	if conn, err = net.Dial("tcp", u.Host); err != nil {
		return
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()

	if _, err = conn.Write([]byte(strings.ReplaceAll(info.originHeader, info.authLine, newAuthLine))); err != nil {
		return
	}

	if info.method == "CONNECT" {
		buffer := make([]byte, 0, 0x100)
		b := make([]byte, 1)
		for {
			if _, err = conn.Read(b); err != nil {
				return
			}
			buffer = append(buffer, b...)
			if b[0] == '\n' && len(buffer) > 4 {
				if bytes.HasSuffix(buffer, []byte("\r\n\r\n")) {
					break
				}
			}

			if len(buffer) >= cap(buffer) {
				return nil, errors.New(string(buffer))
			}
		}

		if !bytes.Contains(buffer, []byte("HTTP/1.1 200 Connection Established")) {
			return nil, errors.New(string(buffer))
		}
	}

	return
}
