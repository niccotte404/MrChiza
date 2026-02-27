package chain

import (
	"bytes"
	"testing"
)

func TestChainDeterminism(t *testing.T) {
	seed := []byte("test-seed-32-bytes-long-enough!!")

	chain1 := NewState(seed, 1)
	chain2 := NewState(seed, 1)

	payloads := [][]byte{
		[]byte("hello world"),
		[]byte("second packet"),
		[]byte("third packet with more data"),
		{0x00, 0x01, 0x02, 0x03},
	}

	for i, payload := range payloads {
		h1 := chain1.Advance(payload)
		h2 := chain2.Advance(payload)
		if !bytes.Equal(h1, h2) {
			t.Errorf("packet %d: chains diverged\n  chain1: %x\n  chain2: %x", i, h1, h2)
		}
	}
}

func TestChainDivergence(t *testing.T) {
	seed := []byte("test-seed-32-bytes-long-enough!!")

	chain1 := NewState(seed, 1)
	chain2 := NewState(seed, 1)

	h1 := chain1.Advance([]byte("same payload"))
	h2 := chain2.Advance([]byte("same payload"))
	if !bytes.Equal(h1, h2) {
		t.Fatal("chains should match after same payload")
	}

	h1 = chain1.Advance([]byte("payload A"))
	h2 = chain2.Advance([]byte("payload B"))
	if bytes.Equal(h1, h2) {
		t.Fatal("chains should diverge after different payloads")
	}
}

func TestChainDepth(t *testing.T) {
	seed := []byte("test-seed-32-bytes-long-enough!!")

	chain1 := NewState(seed, 1)
	chain3 := NewState(seed, 3)

	payload := []byte("test payload")

	h1 := chain1.Advance(payload)
	h3 := chain3.Advance(payload)
	if !bytes.Equal(h1, h3) {
		t.Fatal("first packet should be identical regardless of depth")
	}

	for i := 0; i < 5; i++ {
		chain1.Advance(payload)
		chain3.Advance(payload)
	}

	h1 = chain1.Advance([]byte("divergence test"))
	h3 = chain3.Advance([]byte("divergence test"))

	if len(h1) != 32 || len(h3) != 32 {
		t.Fatal("hashes should be 32 bytes")
	}
}

func TestExtractRange(t *testing.T) {
	seed := []byte("test-seed-32-bytes-long-enough!!")
	c := NewState(seed, 1)

	for i := 0; i < 100; i++ {
		c.Advance([]byte{byte(i)})
		padding := c.PaddingSize(0, 1460)
		if padding < 0 || padding > 1460 {
			t.Errorf("padding %d out of range [0, 1460]", padding)
		}
		delay := c.DelayMs(10, 2000)
		if delay < 10 || delay > 2000 {
			t.Errorf("delay %d out of range [10, 2000]", delay)
		}
	}
}

func TestSeedDerivation(t *testing.T) {
	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	clientSecret, err := SharedSecret(clientKP.PrivateKey, serverKP.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverSecret, err := SharedSecret(serverKP.PrivateKey, clientKP.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clientSecret, serverSecret) {
		t.Fatal("ECDH shared secrets don't match")
	}

	clientSeeds, err := DeriveSeedPair(clientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverSeeds, err := DeriveSeedPair(serverSecret, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clientSeeds.ClientToServer, serverSeeds.ClientToServer) {
		t.Fatal("C2S seeds don't match")
	}
	if !bytes.Equal(clientSeeds.ServerToClient, serverSeeds.ServerToClient) {
		t.Fatal("S2C seeds don't match")
	}
	if !bytes.Equal(clientSeeds.EncryptionKey, serverSeeds.EncryptionKey) {
		t.Fatal("encryption keys don't match")
	}
	if bytes.Equal(clientSeeds.ClientToServer, clientSeeds.ServerToClient) {
		t.Fatal("C2S and S2C seeds should differ")
	}
}

func BenchmarkChainAdvance(b *testing.B) {
	seed := []byte("benchmark-seed-32-bytes-long!!!!")
	c := NewState(seed, 1)
	payload := make([]byte, 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Advance(payload)
	}
}
