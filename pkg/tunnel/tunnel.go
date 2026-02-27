package tunnel

import (
	"errors"
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
	framer    *Framer
	localConn net.Conn

	sendChain *chain.State
	sendMorph *morpher.Morpher

	recvChain *chain.State
	recvMorph *morpher.Morpher

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
	existingFramer *Framer,
) (*Session, error) {
	var framer *Framer
	var err error

	if existingFramer != nil {
		framer = existingFramer
	} else {
		framer, err = NewFramer(conn, encryptionKey)
		if err != nil {
			return nil, err
		}
	}

	return &Session{
		framer:    framer,
		localConn: localConn,
		sendChain: sendChain,
		sendMorph: morpher.New(profile, sendChain),
		recvChain: recvChain,
		recvMorph: morpher.New(profile, recvChain),
	}, nil
}

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

		chainHash := s.sendChain.Current()
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

		s.sendMu.Lock()
		err = s.framer.WriteFrame(frame, chainHash)
		s.sendMu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (s *Session) proxyInbound() error {
	for {
		chainHash := s.recvChain.Current()
		frame, err := s.framer.ReadFrame(chainHash)
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

func (s *Session) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.localConn.Close()
	return nil
}
