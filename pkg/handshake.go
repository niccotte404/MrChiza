package pkg

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/niccotte404/MrChiza/pkg/chain"
)

const (
	MagicV1          = "HCV1"
	EphemeralKeySize = 32
	MagicSize        = 4
)

var (
	ErrBadMagic   = errors.New("handshake: invalid magic/version")
	ErrAuthFailed = errors.New("handshake: authentication failed")
)

type Result struct {
	Seeds    *chain.SeedPair
	IsClient bool
}

func ClientHandshake(conn net.Conn, psk []byte) (*Result, error) {
	ephemeral, err := chain.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake: generate key: %w", err)
	}

	// send magic + ephemeral public key
	msg := make([]byte, 0, MagicSize+EphemeralKeySize)
	msg = append(msg, MagicV1...)
	msg = append(msg, chain.PublicKeyBytes(ephemeral.PublicKey)...)

	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("handshake: write client hello: %w", err)
	}

	// send magic + server ephemeral public key
	resp := make([]byte, MagicSize+EphemeralKeySize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("handshake: read server hello: %w", err)
	}

	if string(resp[:MagicSize]) != MagicV1 {
		return nil, ErrBadMagic
	}

	serverPubBytes := resp[MagicSize:]
	serverPub, err := chain.ParsePublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("handshake: parse server key: %w", err)
	}

	// compute shared secret
	sharedSecret, err := chain.SharedSecret(ephemeral.PrivateKey, serverPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: ecdh: %w", err)
	}

	seeds, err := chain.DeriveSeedPair(sharedSecret, psk)
	if err != nil {
		return nil, fmt.Errorf("handshake: derive seeds: %w", err)
	}

	return &Result{Seeds: seeds, IsClient: true}, nil
}

func ServerHandshake(conn net.Conn, psk []byte) (*Result, error) {
	// receive magic + client ephemeral public key
	msg := make([]byte, MagicSize+EphemeralKeySize)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, fmt.Errorf("handshake: read client hello: %w", err)
	}

	if string(msg[:MagicSize]) != MagicV1 {
		return nil, ErrBadMagic
	}

	clientPubBytes := msg[MagicSize:]
	clientPub, err := chain.ParsePublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("handshake: parse client key: %w", err)
	}

	// generate server ephemeral key pair
	ephemeral, err := chain.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake: generate key: %w", err)
	}

	// send magic + server ephemeral public key
	resp := make([]byte, 0, MagicSize+EphemeralKeySize)
	resp = append(resp, MagicV1...)
	resp = append(resp, chain.PublicKeyBytes(ephemeral.PublicKey)...)

	if _, err := conn.Write(resp); err != nil {
		return nil, fmt.Errorf("handshake: write server hello: %w", err)
	}

	// compute shared secret
	sharedSecret, err := chain.SharedSecret(ephemeral.PrivateKey, clientPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: ecdh: %w", err)
	}

	seeds, err := chain.DeriveSeedPair(sharedSecret, psk)
	if err != nil {
		return nil, fmt.Errorf("handshake: derive seeds: %w", err)
	}

	return &Result{Seeds: seeds, IsClient: false}, nil
}

func NewChainsFromResult(result *Result, depth int) (sendChain, recvChain *chain.State) {
	if result.IsClient {
		// client sends on C2S, receives on S2C
		sendChain = chain.NewState(result.Seeds.ClientToServer, depth)
		recvChain = chain.NewState(result.Seeds.ServerToClient, depth)
	} else {
		// server sends on S2C, receives on C2S
		sendChain = chain.NewState(result.Seeds.ServerToClient, depth)
		recvChain = chain.NewState(result.Seeds.ClientToServer, depth)
	}
	return
}

func PublicKeyFromECDH(key *ecdh.PublicKey) []byte {
	return chain.PublicKeyBytes(key)
}
