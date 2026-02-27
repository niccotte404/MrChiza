package morpher

import (
	"crypto/rand"
	"time"

	"github.com/niccotte404/MrChiza/pkg/chain"
	"github.com/niccotte404/MrChiza/pkg/protocol"
)

type Morpher struct {
	chain        *chain.State
	profile      *Profile
	currentState string
}

func New(chainState *chain.State, profile *Profile) *Morpher {
	return &Morpher{
		chain:        chainState,
		profile:      profile,
		currentState: profile.InitState,
	}
}

type Decision struct {
	PaddingSize int
	Delay       time.Duration
	Fragment    bool
	TargetSize  int
}

func (m *Morpher) Next() Decision {
	m.chain.Advance()

	transVal := m.chain.StateTransition()
	m.currentState = m.profile.SelectTransition(m.currentState, transVal)

	params, ok := m.profile.StateParams[m.currentState]
	if !ok {
		params = StateParameters{
			SizeRange: [2]int{0, 64},
			DelayMs:   [2]int{10, 100},
		}
	}

	paddingSize := m.chain.PaddingSize(params.SizeRange[0], params.SizeRange[1])
	if paddingSize > protocol.MaxPaddingSize {
		paddingSize = protocol.MaxPaddingSize
	}

	delayMs := m.chain.DelayMs(params.DelayMs[0], params.DelayMs[1])
	delay := time.Duration(delayMs) * time.Millisecond
	if delay > protocol.MaxMorphDelay {
		delay = protocol.MaxMorphDelay
	}

	fragment := m.chain.FragmentDecision(0.1)

	return Decision{
		PaddingSize: paddingSize,
		Delay:       delay,
		Fragment:    fragment,
	}
}

func (m *Morpher) AdvanceTo(counter uint64) {
	currentCounter := m.chain.Counter()
	if counter <= currentCounter {
		return
	}
	m.chain.AdvanceTo(counter)
}

func (m *Morpher) CurrentState() string {
	return m.currentState
}

func (m *Morpher) ChainCurrent() []byte {
	return m.chain.Current()
}

func (m *Morpher) ChainCounter() uint64 {
	return m.chain.Counter()
}

func GeneratePadding(size int) []byte {
	if size <= 0 {
		return nil
	}
	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}
