package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/niccotte404/MrChiza/pkg/handshake"
	"github.com/niccotte404/MrChiza/pkg/morpher"
	"github.com/niccotte404/MrChiza/pkg/transport"
	"github.com/niccotte404/MrChiza/pkg/tunnel"
)

func main() {
	listen := flag.String("listen", ":8443", "Listen address")
	psk := flag.String("psk", "", "Pre-shared key (hex encoded)")
	depth := flag.Int("depth", 1, "Hash chain depth")
	profileName := flag.String("profile", "browsing", "Traffic profile")
	certFile := flag.String("cert", "", "TLS certificate file (PEM)")
	keyFile := flag.String("key", "", "TLS private key file (PEM)")
	camoTarget := flag.String("camo", "", "Camouflage target (e.g. www.microsoft.com:443)")
	noTLS := flag.Bool("no-tls", false, "Disable TLS (raw TCP, for testing only)")
	flag.Parse()

	if *psk == "" {
		log.Fatal("--psk is required")
	}

	pskBytes, err := hex.DecodeString(*psk)
	if err != nil {
		log.Fatalf("invalid PSK hex: %v", err)
	}

	profile := selectProfile(*profileName)

	if *noTLS {
		// Raw TCP mode (for local testing)
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		log.Printf("server listening on %s (NO TLS, depth=%d, profile=%s)", *listen, *depth, *profileName)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}
			go handleClient(conn, pskBytes, *depth, profile)
		}
	}

	// TLS mode
	if *certFile == "" || *keyFile == "" {
		// Auto-generate self-signed cert
		log.Println("No cert/key provided, generating self-signed certificate...")
		*certFile, *keyFile, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("generate cert: %v", err)
		}
		defer func(name string) {
			err := os.Remove(name)
			if err != nil {
				log.Printf("remove %s: %v", name, err)
			}
		}(*certFile)
		defer func(name string) {
			err := os.Remove(name)
			if err != nil {
				log.Printf("remove %s: %v", name, err)
			}
		}(*keyFile)
	}

	tlsListener, err := transport.Listen(*listen, &transport.ServerConfig{
		CertFile:         *certFile,
		KeyFile:          *keyFile,
		PSK:              pskBytes,
		CamouflageTarget: *camoTarget,
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer func(tlsListener *transport.Listener) {
		err := tlsListener.Close()
		if err != nil {
			log.Printf("close listener: %v", err)
		}
	}(tlsListener)

	log.Printf("server listening on %s (TLS, depth=%d, profile=%s, camo=%s)",
		*listen, *depth, *profileName, *camoTarget)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleClient(conn, pskBytes, *depth, profile)
	}
}

func handleClient(conn net.Conn, psk []byte, depth int, profile *morpher.Profile) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("close connection: %v", err)
		}
	}(conn)
	remote := conn.RemoteAddr().String()
	log.Printf("[%s] connected", remote)

	result, err := handshake.ServerHandshake(conn, psk)
	if err != nil {
		log.Printf("[%s] handshake: %v", remote, err)
		return
	}
	log.Printf("[%s] handshake ok", remote)

	sendChain, recvChain := handshake.NewChainsFromResult(result, depth)
	sendMorph := morpher.New(sendChain, profile)
	recvMorph := morpher.New(recvChain, profile)

	framer, err := tunnel.NewFramer(conn, result.Seeds.EncryptionKey)
	if err != nil {
		log.Printf("[%s] framer: %v", remote, err)
		return
	}

	destAddrBytes, err := tunnel.ReadControlFrame(framer, recvMorph)
	if err != nil {
		log.Printf("[%s] read dest: %v", remote, err)
		return
	}
	destAddr := string(destAddrBytes)
	log.Printf("[%s] -> %s", remote, destAddr)

	destConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("[%s] dial %s: %v", remote, destAddr, err)
		return
	}
	defer func(destConn net.Conn) {
		err := destConn.Close()
		if err != nil {
			log.Printf("close connection: %v", err)
		}
	}(destConn)

	session, err := tunnel.NewSession(conn, destConn, sendMorph, recvMorph,
		result.Seeds.EncryptionKey, framer)
	if err != nil {
		log.Printf("[%s] session: %v", remote, err)
		return
	}

	if err := session.Run(); err != nil && err != io.EOF {
		log.Printf("[%s] session: %v", remote, err)
	}
	log.Printf("[%s] done", remote)
}

func selectProfile(name string) *morpher.Profile {
	switch name {
	case "streaming":
		return morpher.DefaultStreamingProfile()
	default:
		return morpher.DefaultBrowsingProfile()
	}
}

func generateSelfSignedCert() (certFile, keyFile string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"HashChain VPN"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	cf, _ := os.CreateTemp("", "hcvpn-cert-*.pem")
	err = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return "", "", err
	}
	err = cf.Close()
	if err != nil {
		return "", "", err
	}

	privDER, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.CreateTemp("", "hcvpn-key-*.pem")
	err = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err != nil {
		return "", "", err
	}
	err = kf.Close()
	if err != nil {
		return "", "", err
	}

	return cf.Name(), kf.Name(), nil
}
