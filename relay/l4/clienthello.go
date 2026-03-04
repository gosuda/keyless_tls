package l4

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	tlsRecordHeaderLen       = 5
	tlsHandshakeTypeClientHi = 1
	tlsContentTypeHandshake  = 22
	extServerName            = 0
	extALPN                  = 16
	defaultInspectTimeout    = 2 * time.Second
)

var (
	ErrNotTLSRecord   = errors.New("not a TLS handshake record")
	ErrNotClientHello = errors.New("not a TLS ClientHello")
)

type ClientHelloInfo struct {
	ServerName    string
	ALPNProtocols []string
	ClientAddr    net.Addr
	LocalAddr     net.Addr
}

func InspectClientHello(conn net.Conn, timeout time.Duration) (ClientHelloInfo, net.Conn, error) {
	if conn == nil {
		return ClientHelloInfo{}, nil, errors.New("connection is required")
	}
	if timeout <= 0 {
		timeout = defaultInspectTimeout
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	captured := make([]byte, 0, 1024)

	header := make([]byte, tlsRecordHeaderLen)
	if err := readFullCapture(conn, header, &captured); err != nil {
		return helloWithAddrs(conn), prependConn(conn, captured), fmt.Errorf("read TLS record header: %w", err)
	}
	if header[0] != tlsContentTypeHandshake {
		return helloWithAddrs(conn), prependConn(conn, captured), ErrNotTLSRecord
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen == 0 {
		return helloWithAddrs(conn), prependConn(conn, captured), ErrNotClientHello
	}

	recordBody := make([]byte, recordLen)
	if err := readFullCapture(conn, recordBody, &captured); err != nil {
		return helloWithAddrs(conn), prependConn(conn, captured), fmt.Errorf("read TLS record body: %w", err)
	}

	helloInfo, err := parseClientHelloRecord(recordBody)
	helloInfo.ClientAddr = conn.RemoteAddr()
	helloInfo.LocalAddr = conn.LocalAddr()
	return helloInfo, prependConn(conn, captured), err
}

func parseClientHelloRecord(recordBody []byte) (ClientHelloInfo, error) {
	if len(recordBody) < 4 {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	if recordBody[0] != tlsHandshakeTypeClientHi {
		return ClientHelloInfo{}, ErrNotClientHello
	}

	msgLen := int(recordBody[1])<<16 | int(recordBody[2])<<8 | int(recordBody[3])
	if msgLen <= 0 || 4+msgLen > len(recordBody) {
		return ClientHelloInfo{}, ErrNotClientHello
	}

	msg := recordBody[4 : 4+msgLen]
	if len(msg) < 34 {
		return ClientHelloInfo{}, ErrNotClientHello
	}

	i := 34
	if i >= len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}

	sessLen := int(msg[i])
	i++
	if i+sessLen > len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	i += sessLen

	if i+2 > len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	cipherLen := int(msg[i])<<8 | int(msg[i+1])
	i += 2
	if cipherLen < 2 || i+cipherLen > len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	i += cipherLen

	if i >= len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	compLen := int(msg[i])
	i++
	if compLen < 1 || i+compLen > len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	i += compLen

	if i == len(msg) {
		return ClientHelloInfo{}, nil
	}
	if i+2 > len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}
	extLen := int(msg[i])<<8 | int(msg[i+1])
	i += 2
	if i+extLen > len(msg) {
		return ClientHelloInfo{}, ErrNotClientHello
	}

	end := i + extLen
	info := ClientHelloInfo{}
	for i+4 <= end {
		extType := int(msg[i])<<8 | int(msg[i+1])
		i += 2
		l := int(msg[i])<<8 | int(msg[i+1])
		i += 2
		if i+l > end {
			return ClientHelloInfo{}, ErrNotClientHello
		}
		extData := msg[i : i+l]
		i += l

		switch extType {
		case extServerName:
			if name := parseServerNameExtension(extData); name != "" {
				info.ServerName = NormalizeServerName(name)
			}
		case extALPN:
			info.ALPNProtocols = parseALPNExtension(extData)
		}
	}

	return info, nil
}

func parseServerNameExtension(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	if listLen == 0 || 2+listLen > len(ext) {
		return ""
	}

	i := 2
	end := 2 + listLen
	for i+3 <= end {
		nameType := ext[i]
		i++
		nameLen := int(ext[i])<<8 | int(ext[i+1])
		i += 2
		if i+nameLen > end {
			return ""
		}
		if nameType == 0 {
			return string(ext[i : i+nameLen])
		}
		i += nameLen
	}

	return ""
}

func parseALPNExtension(ext []byte) []string {
	if len(ext) < 2 {
		return nil
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	if listLen == 0 || 2+listLen > len(ext) {
		return nil
	}

	protos := make([]string, 0, 2)
	i := 2
	end := 2 + listLen
	for i < end {
		if i+1 > end {
			return nil
		}
		l := int(ext[i])
		i++
		if l == 0 || i+l > end {
			return nil
		}
		protos = append(protos, string(ext[i:i+l]))
		i += l
	}
	return protos
}

// NormalizeServerName applies canonical SNI normalization: lowercase, trim whitespace, strip trailing dot.
func NormalizeServerName(serverName string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(serverName)), ".")
}

func readFullCapture(conn net.Conn, dst []byte, captured *[]byte) error {
	n, err := io.ReadFull(conn, dst)
	if n > 0 {
		*captured = append(*captured, dst[:n]...)
	}
	if err != nil {
		return err
	}
	return nil
}

func helloWithAddrs(conn net.Conn) ClientHelloInfo {
	return ClientHelloInfo{
		ClientAddr: conn.RemoteAddr(),
		LocalAddr:  conn.LocalAddr(),
	}
}

type preloadedConn struct {
	net.Conn
	prefix *bytes.Reader
}

func prependConn(conn net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		return conn
	}
	return &preloadedConn{Conn: conn, prefix: bytes.NewReader(prefix)}
}

func (c *preloadedConn) Read(p []byte) (int, error) {
	if c.prefix != nil && c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}
