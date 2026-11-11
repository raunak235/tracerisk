package blackbox

import (
	"testing"
	"time"

	"tracerisk/agent"
)

func newTestLedger(t *testing.T, n int) *Ledger {
	t.Helper()
	s, err := NewEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLedger(s, func() time.Time { now = now.Add(time.Second); return now })
	for i := 0; i < n; i++ {
		l.Append("a1", "Test", agent.Action{Decision: "do thing", AmountINR: float64(i * 100), Harmful: i%3 == 0})
	}
	return l
}

func TestCleanLogVerifies(t *testing.T) {
	l := newTestLedger(t, 10)
	if err := Verify(l.Events(), l.PublicKey()); err != nil {
		t.Fatalf("clean log should verify, got %v", err)
	}
}

func TestEditIsDetected(t *testing.T) {
	l := newTestLedger(t, 10)
	ev := l.Events()
	ev[4].Action.AmountINR = 0
	err := Verify(ev, l.PublicKey())
	te, ok := err.(*TamperError)
	if !ok || te.Index != 4 {
		t.Fatalf("expected TamperError at #4, got %v", err)
	}
}

func TestDeletionIsDetected(t *testing.T) {
	l := newTestLedger(t, 10)
	ev := l.Events()
	ev = append(ev[:3], ev[4:]...)
	if Verify(ev, l.PublicKey()) == nil {
		t.Fatal("deleting an event must be detected")
	}
}

func TestRechainWithoutKeyFailsOnSignature(t *testing.T) {
	l := newTestLedger(t, 10)
	ev := l.Events()
	ev[2].Action.AmountINR = 999
	prev := ev[2].PrevHash
	for i := 2; i < len(ev); i++ {
		ev[i].PrevHash = prev
		ev[i].Hash = ComputeHash(ev[i])
		prev = ev[i].Hash
	}
	err := Verify(ev, l.PublicKey())
	te, ok := err.(*TamperError)
	if !ok || te.Index != 2 {
		t.Fatalf("expected signature failure at #2, got %v", err)
	}
}

func TestTruncationNeedsAnchor(t *testing.T) {
	l := newTestLedger(t, 10)
	root := l.MerkleRoot()
	ev := l.Events()[:7]
	if Verify(ev, l.PublicKey()) != nil {
		t.Fatal("a truncated chain is still internally valid")
	}
	if VerifyAnchor(ev, root) == nil {
		t.Fatal("anchor check must catch truncation")
	}
}

func TestEventsReturnsCopy(t *testing.T) {
	l := newTestLedger(t, 3)
	ev := l.Events()
	ev[0].AgentID = "hacker"
	if l.Events()[0].AgentID == "hacker" {
		t.Fatal("Events() must return a copy (encapsulation)")
	}
}
