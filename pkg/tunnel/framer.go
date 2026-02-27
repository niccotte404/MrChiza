package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/niccotte404/MrChiza/pkg/morpher"
	"github.com/niccotte404/MrChiza/pkg/protocol"
)

const (
	controlFramePaddingSize = 32
	maxWireSize             = protocol.MaxFrameSize + protocol.MaxDummySize + 100
)

type Framer struct {
	conn    net.Conn
	aead    cipher.AEAD
	sendCtr uint64 // AEAD nonce counter (always increments, never resets)
	recvCtr uint64 // AEAD nonce counter for receive
}

func NewFramer(conn net.Conn, encryptionKey []byte) (*Framer, error) {
	block, err := aes.NewCipher(encryptionKey[:protocol.KeySize])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Framer{conn: conn, aead: gcm}, nil
}

func (f *Framer) WriteFrame(frame *protocol.Frame, chainHash []byte, seqNum uint64) error {
	polyData, err := frame.MarshalPolymorphic(chainHash)
	if err != nil {
		return err
	}

	plaintext := make([]byte, protocol.SeqSize+len(polyData))
	binary.BigEndian.PutUint64(plaintext[:protocol.SeqSize], seqNum)
	copy(plaintext[protocol.SeqSize:], polyData)

	f.sendCtr++
	nonce := make([]byte, f.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[f.aead.NonceSize()-8:], f.sendCtr)

	ciphertext := f.aead.Seal(nil, nonce, plaintext, nil)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(ciphertext)))

	_, err = f.conn.Write(append(lenBuf, ciphertext...))
	return err
}

func (f *Framer) ReadFrameRaw() (seqNum uint64, polyData []byte, err error) {
	lenBuf := make([]byte, 2)
	if _, err = io.ReadFull(f.conn, lenBuf); err != nil {
		return 0, nil, err
	}

	ciphertextLen := int(binary.BigEndian.Uint16(lenBuf))
	if ciphertextLen > maxWireSize {
		return 0, nil, protocol.ErrFrameTooLarge
	}

	ciphertext := make([]byte, ciphertextLen)
	if _, err = io.ReadFull(f.conn, ciphertext); err != nil {
		return 0, nil, err
	}

	f.recvCtr++
	nonce := make([]byte, f.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[f.aead.NonceSize()-8:], f.recvCtr)

	plaintext, err := f.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, nil, err
	}

	if len(plaintext) < protocol.SeqSize {
		return 0, nil, protocol.ErrFrameTooSmall
	}

	seqNum = binary.BigEndian.Uint64(plaintext[:protocol.SeqSize])
	polyData = plaintext[protocol.SeqSize:]
	return seqNum, polyData, nil
}

func (f *Framer) ReadFrame(chainHash []byte) (uint64, *protocol.Frame, error) {
	seqNum, polyData, err := f.ReadFrameRaw()
	if err != nil {
		return 0, nil, err
	}

	frame, err := protocol.UnmarshalPolymorphic(polyData, chainHash)
	if err != nil {
		return 0, nil, err
	}

	return seqNum, frame, nil
}

func SendControlFrame(framer *Framer, sendMorph *morpher.Morpher, data []byte) error {
	chainHash := sendMorph.ChainCurrent()
	seqNum := sendMorph.ChainCounter()

	// Advance chain
	sendMorph.Next()

	frame := &protocol.Frame{
		Type:    protocol.FrameControl,
		Flags:   protocol.FlagNone,
		Payload: data,
		Padding: morpher.GeneratePadding(controlFramePaddingSize),
	}

	return framer.WriteFrame(frame, chainHash, seqNum)
}

func ReadControlFrame(framer *Framer, recvMorph *morpher.Morpher) ([]byte, error) {
	chainHash := recvMorph.ChainCurrent()

	seqNum, frame, err := framer.ReadFrame(chainHash)
	if err != nil {
		return nil, fmt.Errorf("read control frame: %w", err)
	}

	expectedSeq := recvMorph.ChainCounter()
	if seqNum != expectedSeq {
		return nil, fmt.Errorf("control frame seq mismatch: got %d, expected %d", seqNum, expectedSeq)
	}

	recvMorph.Next()

	return frame.Payload, nil
}
