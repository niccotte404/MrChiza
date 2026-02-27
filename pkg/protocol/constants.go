package protocol

import "time"

const (
	FrameData      byte = 0x01
	FrameControl   byte = 0x02
	FrameKeepalive byte = 0x03

	FlagNone      byte = 0x00
	FlagFragment  byte = 0x01
	FlagFinalFrag byte = 0x02

	MaxFrameSize   = 16384          // 16 KB
	MaxPayloadSize = 16384 - 4 - 16 // minus header minus AEAD tag
	MaxPaddingSize = 1460
	MinFrameSize   = 4

	DefaultChainDepth = 1
	MaxChainDepth     = 8
	HashSize          = 32 // SHA-256

	HashSegPadding  = 0  // hash[0:4]
	HashSegTiming   = 4  // hash[4:8]
	HashSegFragment = 8  // hash[8:12]
	HashSegState    = 12 // hash[12:16]
	HashSegReserved = 16 // hash[16:32]

	MaxMorphDelay = 2000 * time.Millisecond

	NonceSize = 12 // ChaCha20-Poly1305
	KeySize   = 32 // 256-bit keys
	TagSize   = 16 // Poly1305 tag
)
