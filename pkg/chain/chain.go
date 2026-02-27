package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"mrchizaa/pkg/protocol" // todo: поменять на github
	"sync"
)

type State struct {
	mu          sync.Mutex
	depth       int
	history     [][]byte // length = depth
	currentHash []byte   // 32 bytes
	counter     uint64
	seed        []byte
}

func NewState(seed []byte, depth int) *State {
	if depth < 1 {
		depth = protocol.DefaultChainDepth
	}
	if depth > protocol.MaxChainDepth {
		depth = protocol.MaxChainDepth
	}

	initialHash := computeHMAC(seed, nil, 0)

	history := make([][]byte, depth)
	history = append(history, initialHash)

	return &State{
		depth:       depth,
		history:     history,
		currentHash: initialHash,
		counter:     0,
		seed:        seed,
	}
}

func (state *State) AdvanceHash(payload []byte) []byte {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.counter++
	payloadHash := sha256.Sum256(payload)

	var key []byte
	for i := len(state.history) - 1; i >= 0 && i >= len(state.history)-state.depth; i-- {
		key = append(key, state.history[i]...)
	}

	newHash := computeHMAC(key, payloadHash[:], state.counter)

	state.history = append(state.history, newHash)
	if len(state.history) > state.depth*2 {
		state.history = state.history[len(state.history)-state.depth:]
	}

	state.currentHash = newHash
	return newHash
}

func (state *State) Current() []byte {
	state.mu.Lock()
	defer state.mu.Unlock()

	result := make([]byte, len(state.currentHash))
	copy(result, state.currentHash)

	return result
}

func (state *State) Counter() uint64 {
	state.mu.Lock()
	defer state.mu.Unlock()

	return state.counter
}

func (state *State) PaddingSize(minMs, maxMs int) int {
	state.mu.Lock()
	defer state.mu.Unlock()

	return extractRange(state.currentHash, protocol.HashSegTiming, minMs, maxMs)
}

func (state *State) DelayMs(minMs, maxMs int) int {
	state.mu.Lock()
	defer state.mu.Unlock()

	return extractRange(state.currentHash, protocol.HashSegTiming, minMs, maxMs)
}

func (state *State) FragmentDecision(threshold float64) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	val := binary.BigEndian.Uint32(state.currentHash[protocol.HashSegFragment : protocol.HashSegFragment+4])
	normalized := float64(val) / float64(^uint32(0))
	return normalized < threshold
}

func (state *State) StateTransition() float64 {
	state.mu.Lock()
	defer state.mu.Unlock()

	val := binary.BigEndian.Uint32(state.currentHash[protocol.HashSegState : protocol.HashSegState+4])

	return float64(val) / float64(^uint32(0))
}

func computeHMAC(key []byte, data []byte, counter uint64) []byte {
	if len(key) == 0 {
		key = []byte("hashchain-init") // todo: поменять на генерацию через sha256
	}
	hash := hmac.New(sha256.New, key)
	if data != nil {
		hash.Write(data)
	}
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	hash.Write(counterBytes)

	return hash.Sum(nil)
}

func extractRange(hash []byte, offset, min, max int) int {
	if min >= max {
		return min
	}
	val := binary.BigEndian.Uint32(hash[offset : offset+4])
	rangeSize := uint32(max - min + 1)

	return min + int(val%rangeSize)
}
