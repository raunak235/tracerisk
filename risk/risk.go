package risk

import (
	"fmt"

	"tracerisk/agent"
	"tracerisk/blackbox"
)

type Scorer interface {
	Name() string
	Score(events []blackbox.Event) float64
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

type FrequencyScorer struct{}

func (FrequencyScorer) Name() string { return "frequency" }
func (FrequencyScorer) Score(ev []blackbox.Event) float64 {
	if len(ev) == 0 {
		return 0
	}
	harmful := 0
	for _, e := range ev {
		if e.Action.Harmful {
			harmful++
		}
	}
	return clamp01(float64(harmful) / float64(len(ev)) / 0.30) // 30% harmful = max risk
}

type SeverityScorer struct{}

func (SeverityScorer) Name() string { return "severity" }
func (SeverityScorer) Score(ev []blackbox.Event) float64 {
	sum, n := 0.0, 0
	for _, e := range ev {
		if e.Action.Harmful {
			sum += float64(e.Action.Severity)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return clamp01(sum / float64(n) / float64(agent.Critical))
}

type ExposureScorer struct{ CapINR float64 }

func (ExposureScorer) Name() string { return "exposure" }
func (x ExposureScorer) Score(ev []blackbox.Event) float64 {
	total := 0.0
	for _, e := range ev {
		if e.Action.Harmful {
			total += e.Action.AmountINR
		}
	}
	return clamp01(total / x.CapINR)
}

type Composite struct{ parts []weighted }

type weighted struct {
	s Scorer
	w float64
}

func NewComposite() *Composite { return &Composite{} }

func (c *Composite) Add(s Scorer, w float64) *Composite {
	c.parts = append(c.parts, weighted{s, w})
	return c
}

func (c *Composite) Name() string { return "composite" }
func (c *Composite) Score(ev []blackbox.Event) float64 {
	total, wsum := 0.0, 0.0
	for _, p := range c.parts {
		total += p.s.Score(ev) * p.w
		wsum += p.w
	}
	if wsum == 0 {
		return 0
	}
	return total / wsum
}

type Report struct {
	AgentID, Kind  string
	Total, Harmful int
	Frequency      float64
	AvgLossINR     float64
	TotalLossINR   float64
	Score          float64
	Tier           string
	PremiumINR     float64
}

func tier(score float64) string {
	switch {
	case score < 0.25:
		return "A"
	case score < 0.50:
		return "B"
	case score < 0.75:
		return "C"
	}
	return "D"
}

func Assess(events []blackbox.Event, model Scorer, loading float64) []Report {
	groups := map[string][]blackbox.Event{}
	var order []string
	for _, e := range events {
		if _, seen := groups[e.AgentID]; !seen {
			order = append(order, e.AgentID)
		}
		groups[e.AgentID] = append(groups[e.AgentID], e)
	}
	var out []Report
	for _, id := range order {
		ev := groups[id]
		r := Report{AgentID: id, Kind: ev[0].AgentKind, Total: len(ev)}
		for _, e := range ev {
			if e.Action.Harmful {
				r.Harmful++
				r.TotalLossINR += e.Action.AmountINR
			}
		}
		r.Frequency = float64(r.Harmful) / float64(r.Total)
		if r.Harmful > 0 {
			r.AvgLossINR = r.TotalLossINR / float64(r.Harmful)
		}
		r.Score = model.Score(ev)
		r.Tier = tier(r.Score)

		r.PremiumINR = r.Frequency * r.AvgLossINR * 100 * loading
		out = append(out, r)
	}
	return out
}

func (r Report) String() string {
	return fmt.Sprintf("%s (%s): %d/%d harmful, tier %s", r.AgentID, r.Kind, r.Harmful, r.Total, r.Tier)
}
