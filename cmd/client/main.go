package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"

	"github.com/niccotte404/MrChiza/pkg/handshake"
	"github.com/niccotte404/MrChiza/pkg/morpher"
	"github.com/niccotte404/MrChiza/pkg/socks5"
	"github.com/niccotte404/MrChiza/pkg/transport"
	"github.com/niccotte404/MrChiza/pkg/tunnel"
)

func main() {
	localAddr := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	serverAddr := flag.String("server", "", "Remote server address (host:port)")
	psk := flag.String("psk", "", "Pre-shared key (hex encoded)")
	depth := flag.Int("depth", 1, "Hash chain depth")
	profileName := flag.String("profile", "browsing", "Traffic profile")
	sni := flag.String("sni", "", "TLS SNI (default: server hostname)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	noTLS := flag.Bool("no-tls", false, "Disable TLS (raw TCP, for testing only)")
	flag.Parse()

	if *serverAddr == "" {
		log.Fatal("--server is required")
	}
	if *psk == "" {
		log.Fatal("--psk is required")
	}

	pskBytes, err := hex.DecodeString(*psk)
	if err != nil {
		log.Fatalf("invalid PSK hex: %v", err)
	}

	profile := selectProfile(*profileName)

	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	mode := "TLS"
	if *noTLS {
		mode = "NO TLS"
	}
	log.Printf("SOCKS5 proxy on %s -> server %s (%s, depth=%d, profile=%s)",
		*localAddr, *serverAddr, mode, *depth, *profileName)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSOCKS(conn, *serverAddr, pskBytes, *depth, profile, *sni, *insecure, *noTLS)
	}
}

func handleSOCKS(localConn net.Conn, serverAddr string, psk []byte, depth int,
	profile *morpher.Profile, sni string, insecure bool, noTLS bool) {
	defer func(localConn net.Conn) {
		err := localConn.Close()
		if err != nil {
			log.Printf("close connection: %v", err)
		}
	}(localConn)

	req, err := socks5.Handshake(localConn)
	if err != nil {
		log.Printf("[socks] handshake: %v", err)
		return
	}
	log.Printf("[socks] CONNECT %s", req.DestAddr)

	// Connect to server (TLS or raw TCP)
	var serverConn net.Conn
	if noTLS {
		serverConn, err = net.Dial("tcp", serverAddr)
	} else {
		serverConn, err = transport.Dial(&transport.ClientConfig{
			ServerAddr:         serverAddr,
			PSK:                psk,
			SNI:                sni,
			InsecureSkipVerify: insecure,
		})
	}
	if err != nil {
		err := socks5.SendReply(localConn, socks5.RepGeneralFailure, nil)
		if err != nil {
			return
		}
		log.Printf("[tunnel] connect: %v", err)
		return
	}
	defer func(serverConn net.Conn) {
		err := serverConn.Close()
		if err != nil {
			log.Printf("[tunnel] close: %v", err)
		}
	}(serverConn)

	// Hashchain handshake (inside TLS)
	result, err := handshake.ClientHandshake(serverConn, psk)
	if err != nil {
		err := socks5.SendReply(localConn, socks5.RepGeneralFailure, nil)
		if err != nil {
			return
		}
		log.Printf("[tunnel] handshake: %v", err)
		return
	}

	sendChain, recvChain := handshake.NewChainsFromResult(result, depth)
	sendMorph := morpher.New(sendChain, profile)
	recvMorph := morpher.New(recvChain, profile)

	framer, err := tunnel.NewFramer(serverConn, result.Seeds.EncryptionKey)
	if err != nil {
		err := socks5.SendReply(localConn, socks5.RepGeneralFailure, nil)
		if err != nil {
			return
		}
		log.Printf("[tunnel] framer: %v", err)
		return
	}

	err = tunnel.SendControlFrame(framer, sendMorph, []byte(req.DestAddr))
	if err != nil {
		err := socks5.SendReply(localConn, socks5.RepGeneralFailure, nil)
		if err != nil {
			return
		}
		log.Printf("[tunnel] send dest: %v", err)
		return
	}

	err = socks5.SendReply(localConn, socks5.RepSuccess, nil)
	if err != nil {
		return
	}

	session, err := tunnel.NewSession(serverConn, localConn, sendMorph, recvMorph,
		result.Seeds.EncryptionKey, framer)
	if err != nil {
		log.Printf("[tunnel] session: %v", err)
		return
	}

	if err := session.Run(); err != nil && err != io.EOF {
		log.Printf("[tunnel] %s: %v", req.DestAddr, err)
	}
	log.Printf("[tunnel] %s done", req.DestAddr)
}

func selectProfile(name string) *morpher.Profile {
	switch name {
	case "streaming":
		return morpher.DefaultStreamingProfile()
	default:
		return morpher.DefaultBrowsingProfile()
	}
}
