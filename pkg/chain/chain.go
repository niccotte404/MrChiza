package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/niccotte404/MrChiza/pkg/protocol"
)

type State struct {
	mu      sync.Mutex
	depth   int
	history [][]byte // Ring buffer of previous hashes
	current []byte
	counter uint64 // Monotonic packet counter
	seed    []byte
}

func NewState(seed []byte, depth int) *State {
	if depth < 1 {
		depth = protocol.DefaultChainDepth
	}
	if depth > protocol.MaxChainDepth {
		depth = protocol.MaxChainDepth
	}

	initialHash := computeHMAC(seed, nil, 0)

	history := make([][]byte, 0, depth)
	history = append(history, initialHash)

	return &State{
		depth:   depth,
		history: history,
		current: initialHash,
		counter: 0,
		seed:    seed,
	}
}

func (s *State) Advance() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.advanceInternal()
}

func (s *State) advanceInternal() []byte {
	s.counter++

	var key []byte
	for i := len(s.history) - 1; i >= 0 && i >= len(s.history)-s.depth; i-- {
		key = append(key, s.history[i]...)
	}

	newHash := computeHMAC(key, nil, s.counter)

	s.history = append(s.history, newHash)
	if len(s.history) > s.depth*2 {
		s.history = s.history[len(s.history)-s.depth:]
	}

	s.current = newHash
	return newHash
}

// AdvanceTo catch up after packet loss by receiver
func (s *State) AdvanceTo(targetCounter uint64) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if targetCounter <= s.counter {
		return s.current
	}

	for s.counter < targetCounter {
		s.advanceInternal()
	}

	return s.current
}

func (s *State) Current() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]byte, len(s.current))
	copy(result, s.current)
	return result
}

func (s *State) Counter() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counter
}

func (s *State) PaddingSize(minSize, maxSize int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return extractRange(s.current, protocol.HashSegPadding, minSize, maxSize)
}

func (s *State) DelayMs(minMs, maxMs int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return extractRange(s.current, protocol.HashSegTiming, minMs, maxMs)
}

func (s *State) FragmentDecision(threshold float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := binary.BigEndian.Uint32(s.current[protocol.HashSegFragment : protocol.HashSegFragment+4])
	normalized := float64(val) / float64(^uint32(0))
	return normalized < threshold
}

func (s *State) StateTransition() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := binary.BigEndian.Uint32(s.current[protocol.HashSegState : protocol.HashSegState+4])
	return float64(val) / float64(^uint32(0))
}

func computeHMAC(key []byte, data []byte, counter uint64) []byte {
	if len(key) == 0 {
		key = []byte("hashchain-init")
	}
	h := hmac.New(sha256.New, key)
	if data != nil {
		h.Write(data)
	}
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	h.Write(counterBytes)
	return h.Sum(nil)
}

func extractRange(hash []byte, offset int, min, max int) int {
	if min >= max {
		return min
	}
	val := binary.BigEndian.Uint32(hash[offset : offset+4])
	rangeSize := uint32(max - min + 1)
	return min + int(val%rangeSize)
}
