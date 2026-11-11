package blackbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"tracerisk/agent"
)

// GenesisHash is the "previous hash" of the very first event.
var GenesisHash = strings.Repeat("0", 64)

type Event struct {
	Index     int          `json:"index"`
	Timestamp time.Time    `json:"timestamp"`
	AgentID   string       `json:"agent_id"`
	AgentKind string       `json:"agent_kind"`
	Action    agent.Action `json:"action"`
	PrevHash  string       `json:"prev_hash"`
	Hash      string       `json:"hash"`
	Signature string       `json:"signature"`
}

// ComputeHash is exported on purpose: the demo "attacker" in main.go uses it
// to show that knowing the algorithm is NOT enough to cheat (signatures!).
func ComputeHash(e Event) string {
	a := e.Action
	h := sha256.New()
	fmt.Fprintf(h, "%d|%d|%q|%q|%q|%q|%q|%q|%.2f|%d|%t",
		e.Index, e.Timestamp.UTC().UnixNano(), e.AgentID, e.AgentKind,
		a.Perceived, a.Decision, a.Target, e.PrevHash,
		a.AmountINR, int(a.Severity), a.Harmful)
	return hex.EncodeToString(h.Sum(nil))
}

// Ledger is append-only. Its fields are private, so the ONLY way to add data
// is Append(), and the only way to read is Events() which returns a COPY.
type Ledger struct {
	events []Event
	signer Signer
	clock  func() time.Time
}

func NewLedger(s Signer, clock func() time.Time) *Ledger {
	return &Ledger{signer: s, clock: clock}
}

func (l *Ledger) Append(agentID, kind string, a agent.Action) Event {
	prev := GenesisHash
	if n := len(l.events); n > 0 {
		prev = l.events[n-1].Hash
	}
	e := Event{
		Index:     len(l.events),
		Timestamp: l.clock().UTC(),
		AgentID:   agentID,
		AgentKind: kind,
		Action:    a,
		PrevHash:  prev,
	}
	e.Hash = ComputeHash(e)
	e.Signature = hex.EncodeToString(l.signer.Sign([]byte(e.Hash)))
	l.events = append(l.events, e)
	return e
}

func (l *Ledger) Len() int { return len(l.events) }

func (l *Ledger) Events() []Event {
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

func (l *Ledger) PublicKey() ed25519.PublicKey { return l.signer.PublicKey() }
func (l *Ledger) MerkleRoot() string           { return MerkleRoot(l.events) }

// ---------- Export (so you can hand-edit the file and watch it fail) ----------

type Export struct {
	PublicKey  string  `json:"public_key"`
	MerkleRoot string  `json:"merkle_root"`
	Events     []Event `json:"events"`
}

func (l *Ledger) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(Export{
		PublicKey:  hex.EncodeToString(l.PublicKey()),
		MerkleRoot: l.MerkleRoot(),
		Events:     l.events,
	}, "", "  ")
}
