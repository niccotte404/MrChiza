package chain

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/niccotte404/MrChiza/pkg/protocol"
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key length")
	ErrInvalidHkdf      = errors.New("hkdf: output too long")
)

type KeyPair struct {
	PublicKey  *ecdh.PublicKey
	PrivateKey *ecdh.PrivateKey
}

func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PrivateKey: private,
		PublicKey:  private.PublicKey(),
	}, nil
}

func SharedSecret(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	return privateKey.ECDH(peerPublicKey)
}

type SeedPair struct {
	ClientToServer []byte
	ServerToClient []byte
	EncryptionKey  []byte
}

func DeriveSeedPair(sharedSecret []byte, additionalInfo []byte) (*SeedPair, error) {
	salt := []byte("hashchain-vpn-v1")
	prk := hkdfExtract(salt, sharedSecret)

	c2sSeed, err := hkdfExpand(prk, append([]byte("c2s-chain-seed"), additionalInfo...), protocol.KeySize) // todo: переделать хардкод info для гернерации ключей
	if err != nil {
		return nil, err
	}
	s2cSeed, err := hkdfExpand(prk, append([]byte("s2c-chain-seed"), additionalInfo...), protocol.KeySize)
	if err != nil {
		return nil, err
	}
	encKey, err := hkdfExpand(prk, append([]byte("aead-encryption-key"), additionalInfo...), protocol.KeySize)
	if err != nil {
		return nil, err
	}

	return &SeedPair{
		ClientToServer: c2sSeed,
		ServerToClient: s2cSeed,
		EncryptionKey:  encKey,
	}, nil
}

func hkdfExtract(salt []byte, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	hmc := hmac.New(sha256.New, salt)
	hmc.Write(ikm)
	return hmc.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	hashLen := sha256.Size
	n := (length + hashLen - 1) / hashLen
	if n > 255 {
		return nil, ErrInvalidHkdf
	}
	okm := make([]byte, n*hashLen)
	var prev []byte
	for i := 0; i <= n; i++ {
		hmc := hmac.New(sha256.New, prk)
		hmc.Write(prev)
		hmc.Write(info)
		hmc.Write([]byte{byte(i)})
		prev = hmc.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length], nil
}

func PublicKeyBytes(key *ecdh.PublicKey) []byte {
	return key.Bytes()
}

func ParsePublicKey(data []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(data)
}
