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

func New(profile *Profile, chain *chain.State) *Morpher {
	return &Morpher{
		chain:        chain,
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

func (morpher *Morpher) Next(payload []byte) Decision {
	morpher.chain.Advance(payload)

	transitionValue := morpher.chain.StateTransition()
	morpher.currentState = morpher.profile.SelectTransition(morpher.currentState, transitionValue)

	params, ok := morpher.profile.StateParams[morpher.currentState]
	if !ok {
		params = StateParameters{
			SizeRange: [2]int{0, 64},
			DelayMs:   [2]int{10, 100},
		}
	}

	paddingSize := morpher.chain.PaddingSize(params.SizeRange[0], params.SizeRange[1])
	if paddingSize > protocol.MaxPaddingSize {
		paddingSize = protocol.MaxPaddingSize
	}

	delayMs := morpher.chain.DelayMs(params.DelayMs[0], params.DelayMs[1])
	delay := time.Duration(delayMs) * time.Millisecond
	if delay > protocol.MaxMorphDelay {
		delay = protocol.MaxMorphDelay
	}

	fragment := morpher.chain.FragmentDecision(0.1) // todo: вынести в conf

	return Decision{
		PaddingSize: paddingSize,
		Delay:       delay,
		Fragment:    fragment,
		TargetSize:  len(payload) + paddingSize + protocol.PolyHeaderSize,
	}
}

func (morpher *Morpher) CurrentState() string {
	return morpher.currentState
}

func GeneratePadding(size int) []byte {
	if size <= 0 {
		return nil
	}
	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}
