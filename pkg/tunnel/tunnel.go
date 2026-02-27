package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/niccotte404/MrChiza/pkg/chain"
	"github.com/niccotte404/MrChiza/pkg/morpher"
	"github.com/niccotte404/MrChiza/pkg/protocol"
)

var (
	ErrSessionClosed = errors.New("session closed")
)

type Session struct {
	conn      net.Conn // TLS
	localConn net.Conn // Local app connection (SOCKS5 side)

	sendChain *chain.State
	sendMorph *morpher.Morpher

	recvChain *chain.State
	recvMorph *morpher.Morpher

	aead    cipher.AEAD
	sendCtr uint64
	recvCtr uint64
	sendMu  sync.Mutex
	closed  bool
	closeMu sync.Mutex
}

func NewSession(
	conn net.Conn,
	localConn net.Conn,
	sendChain *chain.State,
	recvChain *chain.State,
	profile *morpher.Profile,
	encryptionKey []byte,
) (*Session, error) {
	block, err := aes.NewCipher(encryptionKey[:32])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Session{
		conn:      conn,
		localConn: localConn,
		sendChain: sendChain,
		sendMorph: morpher.New(profile, sendChain),
		recvChain: recvChain,
		recvMorph: morpher.New(profile, recvChain),
		aead:      aead,
	}, nil
}

// Run starts bidirectional proxying
func (s *Session) Run() error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.proxyOutbound() }()
	go func() { errCh <- s.proxyInbound() }()
	err := <-errCh
	s.Close()
	return err
}

func (s *Session) proxyOutbound() error {
	buf := make([]byte, protocol.MaxPayloadSize)
	for {
		n, err := s.localConn.Read(buf)
		if err != nil {
			return err
		}
		payload := buf[:n]

		// get current chain hash before advancing
		chainHash := s.sendChain.Current()
		// advance the chain
		decision := s.sendMorph.Next(payload)

		if decision.Delay > 0 {
			time.Sleep(decision.Delay)
		}

		padding := morpher.GeneratePadding(decision.PaddingSize)
		frame := &protocol.Frame{
			Type:    protocol.FrameData,
			Flags:   protocol.FlagNone,
			Payload: payload,
			Padding: padding,
		}

		if err := s.sendFrame(frame, chainHash); err != nil {
			return err
		}
	}
}

func (s *Session) proxyInbound() error {
	for {
		chainHash := s.recvChain.Current()

		frame, err := s.recvFrame(chainHash)
		if err != nil {
			return err
		}

		s.recvMorph.Next(frame.Payload)

		switch frame.Type {
		case protocol.FrameKeepalive:
			continue
		case protocol.FrameData:
			if _, err := s.localConn.Write(frame.Payload); err != nil {
				return err
			}
		}
	}
}

func (s *Session) sendFrame(frame *protocol.Frame, chainHash []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	plaintext, err := frame.MarshalPolymorphic(chainHash)
	if err != nil {
		return err
	}

	s.sendCtr++
	nonce := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[s.aead.NonceSize()-8:], s.sendCtr)

	ciphertext := s.aead.Seal(nil, nonce, plaintext, nil)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(ciphertext)))

	if _, err := s.conn.Write(append(lenBuf, ciphertext...)); err != nil {
		return err
	}
	return nil
}

func (s *Session) recvFrame(chainHash []byte) (*protocol.Frame, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(s.conn, lenBuf); err != nil {
		return nil, err
	}

	ciphertextLen := int(binary.BigEndian.Uint16(lenBuf))
	if ciphertextLen > protocol.MaxFrameSize+s.aead.Overhead()+100 {
		return nil, protocol.ErrFrameTooLarge
	}

	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(s.conn, ciphertext); err != nil {
		return nil, err
	}

	s.recvCtr++
	nonce := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[s.aead.NonceSize()-8:], s.recvCtr)

	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return protocol.UnmarshalPolymorphic(plaintext, chainHash)
}

func (s *Session) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.conn.Close()
	s.localConn.Close()
	return nil
}
