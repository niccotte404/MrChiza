package morpher

import (
	"encoding/json"
	"os"
)

type Profile struct {
	Name        string                      `json:"name"`
	States      map[string]StateTransitions `json:"states"`
	StateParams map[string]StateParameters  `json:"state_params"`
	InitState   string                      `json:"init_state"`
}

type StateTransitions struct {
	Transitions map[string]float64 `json:"transitions"`
}

type StateParameters struct {
	SizeRange [2]int `json:"size_range"`
	DelayMs   [2]int `json:"delay_ms"`
}

func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (profile *Profile) SelectTransition(currState string, hashValue float64) string {
	state, ok := profile.States[currState]
	if !ok {
		return profile.InitState
	}

	cumulative := 0.0
	for nextState, prob := range state.Transitions {
		cumulative += prob
		if hashValue < cumulative {
			return nextState
		}
	}

	return currState
}

func DefaultBrowsingProfile() *Profile {
	return &Profile{
		Name:      "browsing",
		InitState: "idle",
		States: map[string]StateTransitions{
			"idle": {Transitions: map[string]float64{
				"request": 0.8,
				"idle":    0.2,
			}},
			"request": {Transitions: map[string]float64{
				"burst":   0.9,
				"request": 0.1,
			}},
			"burst": {Transitions: map[string]float64{
				"stream": 0.3,
				"idle":   0.5,
				"burst":  0.2,
			}},
			"stream": {Transitions: map[string]float64{
				"idle":   0.6,
				"stream": 0.3,
				"burst":  0.1,
			}},
		},
		StateParams: map[string]StateParameters{
			"idle":    {SizeRange: [2]int{0, 64}, DelayMs: [2]int{100, 2000}},
			"request": {SizeRange: [2]int{64, 512}, DelayMs: [2]int{5, 50}},
			"burst":   {SizeRange: [2]int{1200, 1460}, DelayMs: [2]int{0, 10}},
			"stream":  {SizeRange: [2]int{512, 1460}, DelayMs: [2]int{10, 100}},
		},
	}
}

func DefaultStreamingProfile() *Profile {
	return &Profile{
		Name:      "streaming",
		InitState: "buffering",
		States: map[string]StateTransitions{
			"buffering": {Transitions: map[string]float64{
				"streaming": 0.85,
				"buffering": 0.15,
			}},
			"streaming": {Transitions: map[string]float64{
				"streaming": 0.75,
				"pause":     0.15,
				"buffering": 0.10,
			}},
			"pause": {Transitions: map[string]float64{
				"streaming": 0.7,
				"idle":      0.3,
			}},
			"idle": {Transitions: map[string]float64{
				"buffering": 0.9,
				"idle":      0.1,
			}},
		},
		StateParams: map[string]StateParameters{
			"buffering": {SizeRange: [2]int{1200, 1460}, DelayMs: [2]int{0, 5}},
			"streaming": {SizeRange: [2]int{1000, 1460}, DelayMs: [2]int{5, 30}},
			"pause":     {SizeRange: [2]int{0, 128}, DelayMs: [2]int{500, 3000}},
			"idle":      {SizeRange: [2]int{0, 64}, DelayMs: [2]int{1000, 5000}},
		},
	}
}
