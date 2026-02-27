package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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
	sendCtr uint64 // Monotonic counter for outgoing frames, used as AEAD nonce
	recvCtr uint64 // Monotonic counter for incoming frames, used as AEAD nonce
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

func (f *Framer) WriteFrame(frame *protocol.Frame, chainHash []byte) error {
	plaintext, err := frame.MarshalPolymorphic(chainHash)
	if err != nil {
		return err
	}

	f.sendCtr++
	nonce := make([]byte, f.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[f.aead.NonceSize()-8:], f.sendCtr)

	ciphertext := f.aead.Seal(nil, nonce, plaintext, nil)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(ciphertext)))

	_, err = f.conn.Write(append(lenBuf, ciphertext...))
	return err
}

func (f *Framer) ReadFrame(chainHash []byte) (*protocol.Frame, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(f.conn, lenBuf); err != nil {
		return nil, err
	}

	ciphertextLen := int(binary.BigEndian.Uint16(lenBuf))
	if ciphertextLen > maxWireSize {
		return nil, protocol.ErrFrameTooLarge
	}

	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(f.conn, ciphertext); err != nil {
		return nil, err
	}

	f.recvCtr++
	nonce := make([]byte, f.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[f.aead.NonceSize()-8:], f.recvCtr)

	plaintext, err := f.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return protocol.UnmarshalPolymorphic(plaintext, chainHash)
}

func SendControlFrame(framer *Framer, sendMorph *morpher.Morpher, data []byte) error {
	chainHash := sendMorph.ChainCurrent()

	sendMorph.Next(data)

	frame := &protocol.Frame{
		Type:    protocol.FrameControl,
		Flags:   protocol.FlagNone,
		Payload: data,
		Padding: morpher.GeneratePadding(controlFramePaddingSize),
	}

	return framer.WriteFrame(frame, chainHash)
}

func ReadControlFrame(framer *Framer, recvMorph *morpher.Morpher) ([]byte, error) {
	chainHash := recvMorph.ChainCurrent()

	frame, err := framer.ReadFrame(chainHash)
	if err != nil {
		return nil, err
	}

	recvMorph.Next(frame.Payload)

	return frame.Payload, nil
}
