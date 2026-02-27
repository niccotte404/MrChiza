package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrFrameTooLarge   = errors.New("frame exceeds maximum allowed size")
	ErrFrameTooSmall   = errors.New("frame exceeds minimum allowed size")
	ErrInvalidType     = errors.New("invalid frame type")
	ErrPayloadTooLarge = errors.New("payload exceeds maximum allowed size")
	ErrInvalidLayout   = errors.New("frame layout verification failed")
)

type Frame struct {
	Type    byte
	Flags   byte
	Payload []byte
	Padding []byte
}

func (frame *Frame) MarshalStatic() ([]byte, error) {
	totalLen := StaticHeaderSize + len(frame.Payload) + len(frame.Padding)
	if totalLen > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	buffer := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buffer[0:2], uint16(totalLen))
	buffer[2] = frame.Type
	buffer[3] = frame.Flags
	binary.BigEndian.PutUint16(buffer[4:6], uint16(len(frame.Payload)))
	copy(buffer[StaticHeaderSize:], frame.Payload)
	copy(buffer[StaticHeaderSize+len(frame.Payload):], frame.Padding)
	return buffer, nil
}

func UnmarshalStatic(reader io.Reader) (*Frame, error) {
	header := make([]byte, StaticHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	totalLen := binary.BigEndian.Uint16(header[0:2])
	if totalLen < StaticHeaderSize {
		return nil, ErrFrameTooSmall
	}
	if totalLen > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	frameType := header[2]
	frameFlags := header[3]
	payloadLen := int(binary.BigEndian.Uint16(header[4:6]))
	body := make([]byte, totalLen-StaticHeaderSize)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}

	if payloadLen > len(body) {
		payloadLen = len(body)
	}

	return &Frame{
		Type:    frameType,
		Flags:   frameFlags,
		Payload: body[:payloadLen],
		Padding: body[payloadLen:],
	}, nil
}

type polyLayout struct {
	dummyLen     int
	slotPerm     [6]int
	xorMask      [6]byte
	payloadFirst bool
}

func computePolyLayout(hash []byte) polyLayout {
	var layout polyLayout
	// dummy prefix: hash[0] mod 16 -> 0..15 bytes
	layout.dummyLen = int(hash[0]) % 16

	perm := [6]int{0, 1, 2, 3, 4, 5}
	for i := 5; i > 0; i-- {
		j := int(hash[6-i]) % (i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	layout.slotPerm = perm

	// xor masks: hash[8..13]
	for i := 0; i < 6; i++ {
		layout.xorMask[i] = hash[8+i]
	}

	// data direction bit: hash[14] bit 0
	layout.payloadFirst = hash[14]&0x01 == 0

	return layout
}

func (frame *Frame) MarshalPolymorphic(chainHash []byte) ([]byte, error) {
	payloadLen := len(frame.Payload)
	paddingLen := len(frame.Padding)
	headerSize := StaticHeaderSize
	totalLen := headerSize + paddingLen + payloadLen

	layout := computePolyLayout(chainHash)
	wireSize := layout.dummyLen + totalLen

	if wireSize > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	buffer := make([]byte, wireSize)
	for i := 0; i < wireSize; i++ {
		buffer[i] = chainHash[16+(i%16)] ^ byte(i)
	}

	canonicalHeader := [6]byte{
		byte(totalLen >> 8),
		byte(totalLen & 0xFF),
		frame.Type,
		frame.Flags,
		byte(payloadLen >> 8),
		byte(payloadLen & 0xFF),
	}

	for i := 0; i < 6; i++ {
		canonicalHeader[i] ^= layout.xorMask[i]
	}

	headerStart := layout.dummyLen
	for pos := 0; pos < 6; pos++ {
		buffer[headerStart+pos] = canonicalHeader[layout.slotPerm[pos]]
	}

	dataStart := headerStart + headerSize
	if layout.payloadFirst {
		copy(buffer[dataStart:], frame.Payload)
		copy(buffer[dataStart+payloadLen:], frame.Padding)
	} else {
		copy(buffer[dataStart:], frame.Padding)
		copy(buffer[dataStart+payloadLen:], frame.Payload)
	}

	return buffer, nil
}

func UnmarshalPolymorphic(data []byte, chainHash []byte) (*Frame, error) {
	layout := computePolyLayout(chainHash)

	if len(data) < layout.dummyLen {
		return nil, ErrFrameTooSmall
	}

	headerStart := layout.dummyLen
	permuted := [6]byte{}
	for i := 0; i < 6; i++ {
		permuted[i] = data[headerStart+i]
	}

	var inversePerm [6]int
	for pos := 0; pos < 6; pos++ {
		inversePerm[layout.slotPerm[pos]] = pos
	}

	var canonicalHeader [6]byte
	for logicalIndex := 0; logicalIndex < 6; logicalIndex++ {
		canonicalHeader[logicalIndex] = permuted[inversePerm[logicalIndex]]
	}

	for i := 0; i < 6; i++ {
		canonicalHeader[i] ^= layout.xorMask[i]
	}

	totalLen := (int(canonicalHeader[0]) << 8) | int(canonicalHeader[1])
	frameType := canonicalHeader[2]
	frameFlag := canonicalHeader[3]
	payloadLen := (int(canonicalHeader[4]) << 8) | int(canonicalHeader[5])

	expectedWireSize := totalLen + layout.dummyLen
	if expectedWireSize != len(data) {
		return nil, ErrInvalidLayout
	}
	if totalLen < 6 {
		return nil, ErrFrameTooSmall
	}

	dataLen := totalLen - StaticHeaderSize
	if payloadLen > dataLen {
		return nil, ErrPayloadTooLarge
	}
	paddingLen := dataLen - payloadLen

	dataStart := headerStart + StaticHeaderSize
	var payload, padding []byte

	if layout.payloadFirst {
		payload = make([]byte, payloadLen)
		copy(payload, data[dataStart:dataStart+payloadLen])
		if paddingLen > 0 {
			padding = make([]byte, paddingLen)
			copy(padding, data[dataStart+payloadLen:])
		}
	} else {
		if paddingLen > 0 {
			padding = make([]byte, paddingLen)
			copy(padding, data[dataStart:dataStart+paddingLen])
		}
		payload = make([]byte, payloadLen)
		copy(payload, data[dataStart+paddingLen:])
	}

	return &Frame{
		Type:    frameType,
		Flags:   frameFlag,
		Padding: padding,
		Payload: payload,
	}, nil
}
