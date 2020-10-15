package main

import (
	"errors"
	"net"
	"pproxy"
)

// ForTestLevel2 ...
func (o *Client) ForTestLevel2() error {
	lClient.Log4Trace("listen test level2:", ":9999")
	s1, err := net.Listen("tcp", ":9999")
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

			pp1 := &pproxy.PProxy{Client: conn, PI: &testLevel2{}}

			newConn, err := pp1.Handshake()
			if err != nil {
				lClient.Log2Error(err)
				return
			}
			defer newConn.Close()

			pproxy.CopyHelper(conn, newConn)
		}(conn)
	}
}

type testLevel2 struct{}

// OnAuth ...
func (o *testLevel2) OnAuth(conn net.Conn, user, password string) (string, error) {
	lClient.Log0Debug("OnAuth level2:", user, password)
	if user == "a" && password == "b" {
		return "", nil
	}
	return "", errors.New("user:password check error")
}

// OnSuccess ...
func (o *testLevel2) OnSuccess(clientConn net.Conn, serverConn net.Conn) {
	lClient.Log0Debug("OnSuccess level2:", clientConn.RemoteAddr().String(), serverConn.RemoteAddr().String())
}
