package omsg

import (
	"net"
	"time"
)

// Client ...
type Client struct {
	ci   ClientInterface
	crc  bool     // 是否启用crc校验
	Conn net.Conn // 用户客户端
}

// Dial 连接到服务器
func Dial(network, address string, ci ClientInterface, crc bool) (*Client, error) {
	return DialTimeout(network, address, 0, ci, crc)
}

// DialTimeout 连接到服务器
func DialTimeout(network, address string, timeout time.Duration, ci ClientInterface, crc bool) (*Client, error) {
	var err error
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}

	o := &Client{Conn: conn, ci: ci, crc: crc}
	go o.hClient()

	return o, nil
}

// 监听数据
func (o *Client) hClient() {
	defer func() {
		// 回调
		o.ci.OnClose()

		o.Close()
	}()

	for {
		cmd, ext, bs, err := Recv(o.crc, o.Conn)
		if err != nil {
			o.ci.OnRecvError(err)
			break
		}
		if err := o.ci.OnData(cmd, ext, bs); err != nil {
			break
		}
	}
}

// Send 向服务器发送数据
func (o *Client) Send(cmd, ext uint16, data []byte) error {
	return Send(o.crc, o.Conn, cmd, ext, data)
}

// Close 关闭链接
func (o *Client) Close() {
	o.Conn.Close()
}
