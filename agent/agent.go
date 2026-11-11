package agent

import (
	"fmt"
	"math/rand"
	"strings"
)

type Severity int

const (
	None Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	}
	return "NONE"
}
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	switch strings.ToUpper(string(b)) {
	case "NONE":
		*s = None
	case "LOW":
		*s = Low
	case "MEDIUM":
		*s = Medium
	case "HIGH":
		*s = High
	case "CRITICAL":
		*s = Critical
	default:
		return fmt.Errorf("unknown severity %q", b)
	}
	return nil
}

type Action struct {
	Perceived string   `json:"perceived"` // input the agent saw
	Decision  string   `json:"decision"`  // what it chose to do
	Target    string   `json:"target"`    // system / customer / machine affected
	AmountINR float64  `json:"amount_inr"`
	Severity  Severity `json:"severity"`
	Harmful   bool     `json:"harmful"`
}

type Agent interface {
	ID() string
	Kind() string
	Act(step int) Action
}

type Base struct {
	id   string
	kind string
	rng  *rand.Rand
}

func NewBase(id, kind string, seed int64) Base {
	return Base{id: id, kind: kind, rng: rand.New(rand.NewSource(seed))}
}

func (b Base) ID() string   { return b.id }
func (b Base) Kind() string { return b.kind }

func (b Base) roll() float64 { return b.rng.Float64() }

func (b Base) pick(options []string) string { return options[b.rng.Intn(len(options))] }

type DevOpsAgent struct {
	Base
	services []string
}

func NewDevOpsAgent(id string, seed int64) *DevOpsAgent {
	return &DevOpsAgent{
		Base:     NewBase(id, "DevOps", seed),
		services: []string{"payments-api", "orders-db", "auth-service", "search-cluster"},
	}
}

func (d *DevOpsAgent) Act(step int) Action {
	svc := d.pick(d.services)
	seen := fmt.Sprintf("%s: CPU %d%%, 5xx errors rising", svc, 70+d.rng.Intn(30))
	r := d.roll()
	switch {
	case r < 0.08:
		return Action{seen, "DROP production database replica", svc, 450000, Critical, true}
	case r < 0.18:
		return Action{seen, "force-restart all pods without draining traffic", svc, 85000, High, true}
	case r < 0.26:
		return Action{seen, "roll back to wrong release (v1.8 instead of v2.1)", svc, 22000, Medium, true}
	}
	return Action{seen, "scale out +2 replicas", svc, 0, None, false}
}

type RefundAgent struct {
	Base
}

func NewRefundAgent(id string, seed int64) *RefundAgent {
	return &RefundAgent{Base: NewBase(id, "Refund", seed)}
}

func (r *RefundAgent) Act(step int) Action {
	order := 1200 + r.rng.Intn(8000)
	seen := fmt.Sprintf("Ticket #%d: customer says item damaged, order value Rs %d", 4000+step, order)
	roll := r.roll()
	switch {
	case roll < 0.05:
		return Action{seen, "refund 10x amount (parsing error on decimal)", "customer-wallet", float64(order * 10), Critical, true}
	case roll < 0.18:
		return Action{seen, "approve duplicate refund for same order", "customer-wallet", float64(order), Medium, true}
	case roll < 0.25:
		return Action{seen, "refund fraudster without verification", "customer-wallet", float64(order), High, true}
	}
	return Action{seen, "approve verified refund", "customer-wallet", 0, None, false}
}

type RobotAgent struct {
	Base
	bays []string
}

func NewRobotAgent(id string, seed int64) *RobotAgent {
	return &RobotAgent{
		Base: NewBase(id, "Robot", seed),
		bays: []string{"bay-3", "bay-7", "bay-12", "bay-19"},
	}
}

func (r *RobotAgent) Act(step int) Action {
	bay := r.pick(r.bays)
	seen := fmt.Sprintf("Lidar: object in %s path, confidence %d%%", bay, 50+r.rng.Intn(40))
	roll := r.roll()
	switch {
	case roll < 0.04:
		return Action{seen, "ignore obstruction and keep moving at full speed", bay, 300000, Critical, true}
	case roll < 0.12:
		return Action{seen, "drop pallet while stacking", bay, 40000, Medium, true}
	}
	return Action{seen, "stop, re-scan, then proceed", bay, 0, None, false}
}

var (
	_ Agent = (*DevOpsAgent)(nil)
	_ Agent = (*RefundAgent)(nil)
	_ Agent = (*RobotAgent)(nil)
)
