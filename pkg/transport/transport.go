package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	AuthTokenSize = 64 // 32B pubkey + 32B HMAC
	AuthTimeout   = 10 * time.Second
)

var (
	ErrAuthFailed = errors.New("transport: authentication failed")
)

type ServerConfig struct {
	// TLS
	CertFile string
	KeyFile  string

	PSK []byte

	CamouflageTarget string
}

type ClientConfig struct {
	ServerAddr         string
	PSK                []byte
	SNI                string
	InsecureSkipVerify bool
}

type Listener struct {
	tlsListener net.Listener
	psk         []byte
	camoTarget  string
}

func Listen(addr string, cfg *ServerConfig) (*Listener, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("transport: load cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("transport: listen: %w", err)
	}

	return &Listener{
		tlsListener: ln,
		psk:         cfg.PSK,
		camoTarget:  cfg.CamouflageTarget,
	}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.tlsListener.Accept()
		if err != nil {
			return nil, err
		}

		// Read auth token with timeout
		err = conn.SetReadDeadline(time.Now().Add(AuthTimeout))
		if err != nil {
			return nil, err
		}
		authBuf := make([]byte, AuthTokenSize)
		_, err = io.ReadFull(conn, authBuf)
		err = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, err
		} // clear deadline

		if err != nil {
			go l.proxyCamouflage(conn, nil)
			continue
		}

		if !verifyAuthToken(authBuf, l.psk) {
			go l.proxyCamouflage(conn, authBuf)
			continue
		}

		return conn, nil
	}
}

func (l *Listener) proxyCamouflage(clientConn net.Conn, initialData []byte) {
	defer clientConn.Close()

	if l.camoTarget == "" {
		return
	}

	targetConn, err := tls.Dial("tcp", l.camoTarget, &tls.Config{
		ServerName: l.camoTarget[:len(l.camoTarget)-4], // strip :443
	})
	if err != nil {
		return
	}
	defer targetConn.Close()

	if len(initialData) > 0 {
		targetConn.Write(initialData)
	}

	// Bidirectional proxy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()
	<-done
}

func (l *Listener) Close() error {
	return l.tlsListener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.tlsListener.Addr()
}

func Dial(cfg *ClientConfig) (net.Conn, error) {
	tlsCfg := &tls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", cfg.ServerAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("transport: tls dial: %w", err)
	}

	token := generateAuthToken(cfg.PSK)
	if _, err := conn.Write(token); err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: write auth: %w", err)
	}

	return conn, nil
}

func generateAuthToken(psk []byte) []byte {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		// Fallback to pure random if keygen fails
		token := make([]byte, AuthTokenSize)
		rand.Read(token)
		return token
	}

	pubBytes := priv.PublicKey().Bytes()
	mac := computeAuthMAC(pubBytes, psk)

	token := make([]byte, AuthTokenSize)
	copy(token[:32], pubBytes)
	copy(token[32:], mac)
	return token
}

func verifyAuthToken(token []byte, psk []byte) bool {
	if len(token) != AuthTokenSize {
		return false
	}

	pubBytes := token[:32]
	claimedMAC := token[32:]
	expectedMAC := computeAuthMAC(pubBytes, psk)

	match := byte(0)
	for i := 0; i < 32; i++ {
		match |= claimedMAC[i] ^ expectedMAC[i]
	}
	return match == 0
}

func computeAuthMAC(pubBytes, psk []byte) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write(pubBytes)

	window := make([]byte, 8)
	binary.BigEndian.PutUint64(window, uint64(time.Now().Unix()/30))
	h.Write(window)

	return h.Sum(nil)
}
