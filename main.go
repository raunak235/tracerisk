package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"tracerisk/agent"
	"tracerisk/blackbox"
	"tracerisk/risk"
)

const (
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	dim    = "\033[2m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "verify" {
		os.Exit(verifyFile(os.Args[2:]))
	}
	rounds := flag.Int("rounds", 20, "rounds of agent activity (3 agents act each round)")
	exportPath := flag.String("export", "", "write the ledger to this JSON file")
	flag.Parse()
	runDemo(*rounds, *exportPath)
}

// ------------------------------------------------------------------ demo

func runDemo(rounds int, exportPath string) {
	banner()

	// 1. Build the ledger. Signer is an interface; we hand it a concrete Ed25519 one.
	signer, err := blackbox.NewEd25519Signer()
	must(err)
	t := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { t = t.Add(37 * time.Second); return t }
	ledger := blackbox.NewLedger(signer, clock)

	// 2. Polymorphism: one slice, three different concrete types.
	agents := []agent.Agent{
		agent.NewDevOpsAgent("devops-01", 11),
		agent.NewRefundAgent("refund-01", 22),
		agent.NewRobotAgent("robot-01", 33),
	}

	title("1. AGENTS WORK - the black box records everything")
	step := 0
	for r := 0; r < rounds; r++ {
		for _, a := range agents {
			ev := ledger.Append(a.ID(), a.Kind(), a.Act(step)) // same call, different behaviour
			if step < 8 || ev.Action.Severity == agent.Critical {
				printEvent(ev)
			} else if step == 8 {
				fmt.Printf("%s   ... (only CRITICAL events shown from here) ...%s\n", dim, reset)
			}
			step++
		}
	}
	events := ledger.Events()
	pub := ledger.PublicKey()
	root := ledger.MerkleRoot()
	fmt.Printf("\n   %d events logged.  Merkle root (published anchor): %s%s...%s\n", len(events), cyan, root[:24], reset)

	title("2. VERIFY the honest log")
	report("honest log", blackbox.Verify(events, pub))

	// ---------------- attacks ----------------
	target := firstIndex(events, func(e blackbox.Event) bool {
		return e.Action.Harmful && e.Action.Severity == agent.Critical
	})
	title("3. ATTACKS - a company tries to hide its agent's worst incident")
	fmt.Printf("   Target: event #%d  %s%s%s\n\n", target, yellow, events[target].Action.Decision, reset)

	// Attack A: quietly edit the event.
	a := clone(events)
	a[target].Action.AmountINR = 0
	a[target].Action.Harmful = false
	a[target].Action.Severity = agent.None
	fmt.Printf(" %sAttack A%s  edit the loss to Rs 0 and mark it harmless\n", bold, reset)
	report("tampered log A", blackbox.Verify(a, pub))

	// Attack B: delete the embarrassing event.
	b := clone(events)
	b = append(b[:target], b[target+1:]...)
	fmt.Printf("\n %sAttack B%s  delete the event completely\n", bold, reset)
	report("tampered log B", blackbox.Verify(b, pub))

	// Attack C: smart attacker edits AND recomputes every hash after it.
	c := clone(events)
	c[target].Action.AmountINR = 0
	c[target].Action.Harmful = false
	c[target].Action.Severity = agent.None
	prev := c[target].PrevHash
	for i := target; i < len(c); i++ {
		c[i].PrevHash = prev
		c[i].Hash = blackbox.ComputeHash(c[i]) // attacker knows the algorithm...
		prev = c[i].Hash
	}
	fmt.Printf("\n %sAttack C%s  edit + re-compute the whole hash chain (smart attacker)\n", bold, reset)
	report("tampered log C", blackbox.Verify(c, pub))
	fmt.Printf("   %s...but they can't forge Ed25519 signatures without the private key.%s\n", dim, reset)

	// Attack D: chop off the newest events. The chain alone can't see this.
	d := clone(events)[:len(events)-6]
	fmt.Printf("\n %sAttack D%s  truncate the last 6 events\n", bold, reset)
	report("chain check only", blackbox.Verify(d, pub))
	if err := blackbox.VerifyAnchor(d, root); err != nil {
		fmt.Printf("   %s✗ anchor check: %v%s\n", red, err, reset)
		fmt.Printf("   %s→ caught, because the Merkle root was published earlier.%s\n", green, reset)
	}

	// ---------------- pricing ----------------
	title("4. PRICE THE RISK (only from a log that passed verification)")
	model := risk.NewComposite().
		Add(risk.FrequencyScorer{}, 0.4).
		Add(risk.SeverityScorer{}, 0.3).
		Add(risk.ExposureScorer{CapINR: 1_500_000}, 0.3)
	reports := risk.Assess(events, model, 1.35)
	fmt.Printf("   %-11s %-8s %-9s %-13s %-6s %-5s %s\n", "AGENT", "KIND", "HARMFUL", "LOSS", "SCORE", "TIER", "PREMIUM /100 actions")
	totalHonest := 0.0
	for _, r := range reports {
		totalHonest += r.PremiumINR
		col := map[string]string{"A": green, "B": green, "C": yellow, "D": red}[r.Tier]
		fmt.Printf("   %-11s %-8s %2d/%-6d %-13s %-6.2f %s%-5s%s %s\n",
			r.AgentID, r.Kind, r.Harmful, r.Total, inr(r.TotalLossINR), r.Score, col, r.Tier, reset, inr(r.PremiumINR))
	}
	doctored := 0.0
	for _, r := range risk.Assess(a, model, 1.35) {
		doctored += r.PremiumINR
	}
	fmt.Printf("\n   Total premium, honest log:   %s%s%s\n", bold, inr(totalHonest), reset)
	fmt.Printf("   Total premium, doctored log: %s  %s(what the cheater hoped for)%s\n", inr(doctored), dim, reset)
	fmt.Printf("   %sThat gap is exactly why insurers need a tamper-evident record.%s\n", green, reset)

	if exportPath != "" {
		data, err := ledger.ExportJSON()
		must(err)
		must(os.WriteFile(exportPath, data, 0o644))
		fmt.Printf("\n   Saved %s. Edit any value in it, then run:  %sgo run . verify %s%s\n", exportPath, cyan, exportPath, reset)
	}
	fmt.Println()
}

// ------------------------------------------------------------------ verify subcommand

func verifyFile(args []string) int {
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Println("cannot read file:", err)
		return 2
	}
	var ex blackbox.Export
	if err := json.Unmarshal(raw, &ex); err != nil {
		fmt.Println("not a valid ledger file:", err)
		return 2
	}
	keyHex := ex.PublicKey
	if len(args) > 1 {
		keyHex = args[1] // pinned key supplied by the verifier
	}
	pub, err := hex.DecodeString(keyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Println("bad public key")
		return 2
	}
	fmt.Printf("Verifying %d events against key %s...\n", len(ex.Events), keyHex[:16])
	if err := blackbox.Verify(ex.Events, pub); err != nil {
		fmt.Printf("%s✗ %v%s\n", red, err, reset)
		return 1
	}
	if err := blackbox.VerifyAnchor(ex.Events, ex.MerkleRoot); err != nil {
		fmt.Printf("%s✗ %v%s\n", red, err, reset)
		return 1
	}
	fmt.Printf("%s✓ ledger is intact: chain, signatures and Merkle root all match.%s\n", green, reset)
	return 0
}

// ------------------------------------------------------------------ helpers

func report(label string, err error) {
	if err == nil {
		fmt.Printf("   %s✓ %s: all %s checks passed%s\n", green, label, "chain + signature", reset)
		return
	}
	fmt.Printf("   %s✗ %s: %v%s\n", red, label, err, reset)
}

func printEvent(e blackbox.Event) {
	col := green
	switch e.Action.Severity {
	case agent.Critical:
		col = red
	case agent.High, agent.Medium, agent.Low:
		col = yellow
	}
	fmt.Printf("   #%-3d %s%-10s%s %s%-48s%s %s%s%s %s→ %s%s\n",
		e.Index, cyan, e.AgentID, reset, col, trunc(e.Action.Decision, 48), reset,
		dim, inr(e.Action.AmountINR), reset, dim, e.Hash[:10], reset)
}

func clone(ev []blackbox.Event) []blackbox.Event {
	out := make([]blackbox.Event, len(ev))
	copy(out, ev)
	return out
}

func firstIndex(ev []blackbox.Event, pred func(blackbox.Event) bool) int {
	for i, e := range ev {
		if pred(e) {
			return i
		}
	}
	return 0
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// inr formats a number with Indian digit grouping: 1234567 -> Rs 12,34,567
func inr(v float64) string {
	s := strconv.FormatInt(int64(math.Round(v)), 10)
	if len(s) <= 3 {
		return "Rs " + s
	}
	last3, rest := s[len(s)-3:], s[:len(s)-3]
	var parts []string
	for len(rest) > 2 {
		parts = append([]string{rest[len(rest)-2:]}, parts...)
		rest = rest[:len(rest)-2]
	}
	if rest != "" {
		parts = append([]string{rest}, parts...)
	}
	return "Rs " + strings.Join(parts, ",") + "," + last3
}

func title(s string) { fmt.Printf("\n%s%s== %s ==%s\n\n", bold, cyan, s, reset) }

func must(err error) {
	if err != nil {
		fmt.Println("fatal:", err)
		os.Exit(1)
	}
}

func banner() {
	fmt.Printf("%s%s\n  ╔══════════════════════════════════════════╗\n  ║  TRACERISK  -  black box for AI agents   ║\n  ╚══════════════════════════════════════════╝%s\n", bold, cyan, reset)
}
