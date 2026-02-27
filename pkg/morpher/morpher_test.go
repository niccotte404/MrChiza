package morpher

import (
	"testing"

	"github.com/niccotte404/MrChiza/pkg/chain"
)

func TestMorpherDeterminism(t *testing.T) {
	seed := []byte("test-seed-32-bytes-long-enough!!")
	profile := DefaultBrowsingProfile()

	chain1 := chain.NewState(seed, 1)
	chain2 := chain.NewState(seed, 1)

	morph1 := New(chain1, profile)
	morph2 := New(chain2, profile)

	payloads := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("<html><body>Hello World</body></html>"),
		[]byte("some more data flowing through the tunnel"),
	}

	for i := range payloads {
		d1 := morph1.Next()
		d2 := morph2.Next()

		if d1.PaddingSize != d2.PaddingSize {
			t.Errorf("packet %d: padding mismatch: %d vs %d", i, d1.PaddingSize, d2.PaddingSize)
		}
		if d1.Delay != d2.Delay {
			t.Errorf("packet %d: delay mismatch: %v vs %v", i, d1.Delay, d2.Delay)
		}
		if d1.Fragment != d2.Fragment {
			t.Errorf("packet %d: fragment mismatch: %v vs %v", i, d1.Fragment, d2.Fragment)
		}
		if morph1.CurrentState() != morph2.CurrentState() {
			t.Errorf("packet %d: state mismatch: %s vs %s", i, morph1.CurrentState(), morph2.CurrentState())
		}
	}
}

func TestMorpherStateTransitions(t *testing.T) {
	seed := []byte("test-seed-32-bytes-long-enough!!")
	profile := DefaultBrowsingProfile()
	c := chain.NewState(seed, 1)
	m := New(c, profile)

	states := make(map[string]int)
	for i := 0; i < 1000; i++ {
		m.Next()
		states[m.CurrentState()]++
	}

	for state := range profile.States {
		if count, ok := states[state]; !ok || count == 0 {
			t.Errorf("state %q was never visited in 1000 iterations", state)
		}
	}

	t.Logf("State distribution over 1000 packets: %v", states)
}

func TestPaddingGeneration(t *testing.T) {
	padding := GeneratePadding(100)
	if len(padding) != 100 {
		t.Errorf("expected 100 bytes, got %d", len(padding))
	}

	allZero := true
	for _, b := range padding {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("padding is all zeros — unlikely with crypto/rand")
	}

	// Zero-size padding
	padding = GeneratePadding(0)
	if padding != nil {
		t.Error("expected nil for zero padding")
	}
}

func TestStreamingProfile(t *testing.T) {
	seed := []byte("streaming-test-seed-32-bytes!!!!")
	profile := DefaultStreamingProfile()
	c := chain.NewState(seed, 1)
	m := New(c, profile)

	states := make(map[string]int)
	for i := 0; i < 1000; i++ {
		m.Next()
		states[m.CurrentState()]++
	}

	if states["streaming"]+states["buffering"] < 500 {
		t.Errorf("streaming profile should be mostly streaming/buffering, got: %v", states)
	}

	t.Logf("Streaming state distribution: %v", states)
}
