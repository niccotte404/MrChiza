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

	utls "github.com/refraction-networking/utls"
)

const (
	AuthTokenSize = 64 // 32B ephemeral pubkey + 32B HMAC
	AuthTimeout   = 10 * time.Second
)

var (
	ErrAuthFailed = errors.New("transport: authentication failed")
)

type Fingerprint int

const (
	FingerprintChrome Fingerprint = iota
	FingerprintFirefox
	FingerprintSafari
	FingerprintRandom
)

type ServerConfig struct {
	CertFile         string
	KeyFile          string
	PSK              []byte
	CamouflageTarget string
}

type ClientConfig struct {
	ServerAddr         string
	PSK                []byte
	SNI                string
	Fingerprint        Fingerprint
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

		conn.SetReadDeadline(time.Now().Add(AuthTimeout))
		authBuf := make([]byte, AuthTokenSize)
		_, err = io.ReadFull(conn, authBuf)
		conn.SetReadDeadline(time.Time{})

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

	host := stripPort(l.camoTarget)

	targetConn, err := tls.Dial("tcp", l.camoTarget, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return
	}
	defer targetConn.Close()

	if len(initialData) > 0 {
		targetConn.Write(initialData)
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(targetConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, targetConn); done <- struct{}{} }()
	<-done
}

func (l *Listener) Close() error   { return l.tlsListener.Close() }
func (l *Listener) Addr() net.Addr { return l.tlsListener.Addr() }

func Dial(cfg *ClientConfig) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = stripPort(cfg.ServerAddr)
	} else {
		sni = stripPort(sni)
	}

	rawConn, err := net.DialTimeout("tcp", cfg.ServerAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("transport: tcp dial %s: %w", cfg.ServerAddr, err)
	}

	utlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         utls.VersionTLS13,
	}, fingerprintToUTLS(cfg.Fingerprint))

	if err := utlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport: tls handshake with %s (sni=%s): %w",
			cfg.ServerAddr, sni, err)
	}

	token := generateAuthToken(cfg.PSK)
	if _, err := utlsConn.Write(token); err != nil {
		utlsConn.Close()
		return nil, fmt.Errorf("transport: write auth token: %w", err)
	}

	return utlsConn, nil
}

func fingerprintToUTLS(fp Fingerprint) utls.ClientHelloID {
	switch fp {
	case FingerprintFirefox:
		return utls.HelloFirefox_120
	case FingerprintSafari:
		return utls.HelloSafari_Auto
	case FingerprintRandom:
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_120
	}
}

func generateAuthToken(psk []byte) []byte {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
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

	now := time.Now().Unix()
	for _, window := range []int64{now / 30, (now / 30) - 1} {
		expected := computeAuthMACWithWindow(pubBytes, psk, window)
		if constantTimeEqual(claimedMAC, expected) {
			return true
		}
	}
	return false
}

func computeAuthMAC(pubBytes, psk []byte) []byte {
	return computeAuthMACWithWindow(pubBytes, psk, time.Now().Unix()/30)
}

func computeAuthMACWithWindow(pubBytes, psk []byte, window int64) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write(pubBytes)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(window))
	h.Write(buf)
	return h.Sum(nil)
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
