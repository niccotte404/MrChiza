package pkg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Version5 = 0x05

	AuthNone   = 0x00
	AuthReject = 0xFF

	CmdConnect = 0x01

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	RepSuccess          = 0x00
	RepGeneralFailure   = 0x01
	RepConnNotAllowed   = 0x02
	RepNetworkUnreach   = 0x03
	RepHostUnreach      = 0x04
	RepConnRefused      = 0x05
	RepCmdNotSupported  = 0x07
	RepAddrNotSupported = 0x08
)

var (
	ErrUnsupportedVersion = errors.New("socks: unsupported version")
	ErrNoAcceptableAuth   = errors.New("socks: no acceptable auth method")
	ErrUnsupportedCmd     = errors.New("socks: unsupported command")
)

type Request struct {
	DestAddr string
	DestHost string
	DestPort uint16
}

func Handshake(conn net.Conn) (*Request, error) {
	// Client: [VER=5][NMETHODS][METHODS...]
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("socks: read auth header: %w", err)
	}
	if header[0] != Version5 {
		return nil, ErrUnsupportedVersion
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("socks: read methods: %w", err)
	}

	// No-auth only. Just for now
	hasNoAuth := false
	for _, m := range methods {
		if m == AuthNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{Version5, AuthReject})
		return nil, ErrNoAcceptableAuth
	}

	// Server: [VER=5][METHOD=0]
	if _, err := conn.Write([]byte{Version5, AuthNone}); err != nil {
		return nil, fmt.Errorf("socks: write auth response: %w", err)
	}

	// Client: [VER=5][CMD][RSV=0][ATYP][DST.ADDR][DST.PORT]
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return nil, fmt.Errorf("socks: read request header: %w", err)
	}
	if reqHeader[0] != Version5 {
		return nil, ErrUnsupportedVersion
	}
	if reqHeader[1] != CmdConnect {
		SendReply(conn, RepCmdNotSupported, nil)
		return nil, ErrUnsupportedCmd
	}

	atyp := reqHeader[3]
	var host string

	switch atyp {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("socks: read ipv4: %w", err)
		}
		host = net.IP(addr).String()

	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("socks: read domain len: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("socks: read domain: %w", err)
		}
		host = string(domain)

	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("socks: read ipv6: %w", err)
		}
		host = net.IP(addr).String()

	default:
		SendReply(conn, RepAddrNotSupported, nil)
		return nil, fmt.Errorf("socks: unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("socks: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return &Request{
		DestAddr: net.JoinHostPort(host, strconv.Itoa(int(port))),
		DestHost: host,
		DestPort: port,
	}, nil
}

func SendReply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	// [VER=5][REP][RSV=0][ATYP=1][BND.ADDR=4B][BND.PORT=2B]
	reply := []byte{Version5, rep, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}

	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			ip := tcpAddr.IP.To4()
			if ip != nil {
				copy(reply[4:8], ip)
			}
			binary.BigEndian.PutUint16(reply[8:10], uint16(tcpAddr.Port))
		}
	}

	_, err := conn.Write(reply)
	return err
}
