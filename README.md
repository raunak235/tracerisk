# TraceRisk: a tamper-evident black box for AI agents (Go)

> Starting version generated with AI assistance. I'm reading it file by
> file and extending it. See "My changes" below.

Cryptography project. A learning prototype of the TraceRisk idea:

* **Layer A - Black Box (`blackbox/`)**: every action an AI agent takes is written to a
  cryptographically tamper-evident log.
* **Layer B - Risk Model (`risk/`)**: verified logs are turned into a risk score, a tier (A-D)
  and an insurance premium.

## Run it

```bash
go run .                       # full demo: agents work -> attacks -> pricing
go run . -export ledger.json   # same, and saves the ledger
go run . verify ledger.json    # verify a saved ledger
go test ./...                  # unit tests
```

**Live demo trick:** run with `-export`, open `ledger.json`, change any `"amount_inr"` value,
then run `go run . verify ledger.json` and watch it name the exact event you touched.

## Cryptography (and what each piece stops)

| Tool | Stops |
|---|---|
| **SHA-256 hash chain** (`prev_hash` -> `hash`) | Editing or deleting an event (every later link breaks). |
| **Ed25519 signatures** (sign each hash) | A smart attacker who edits an event *and recomputes the whole chain*. They don't have the private key. |
| **Merkle root** (`MerkleRoot`) | Chopping off the *last* events. A chain can't see that, but a previously published root can. |

The demo runs four attacks (A edit, B delete, C edit+rechain, D truncate); each is caught by a different layer.

## Project layout

```
tracerisk/
  main.go               demo + `verify` command
  agent/agent.go        Agent interface, Base, 3 concrete agents, Severity enum
  blackbox/ledger.go    Event, Ledger, SHA-256 hashing, export
  blackbox/signer.go    Signer interface + Ed25519 implementation
  blackbox/verify.go    Verify(), MerkleRoot(), VerifyAnchor(), TamperError
  blackbox/ledger_test.go
  risk/risk.go          Scorer interface, 3 scorers, Composite, Assess()
```

## Honest limitations (say these before your teacher asks)

* Agent behaviour is **simulated** with a seeded RNG, not real AI agents.
* `verify` trusts the public key inside the file unless you pass your own: `go run . verify file.json <pubkey-hex>`. In real life you'd pin the key and publish the Merkle root somewhere the logger can't edit.
* Risk weights and premium formula are **illustrative**, not real actuarial science.
* A compromised logger (private key stolen) could sign false events. Real systems add hardware security modules and external timestamping.

## Ideas to extend if you have time

1. Add a `HealthcareAgent` (new type -> `main.go` needs **zero** other changes. That's polymorphism).
2. Add a `Scorer` for "harmful actions in the last hour".
3. Write a `Signer` that wraps a different algorithm (ECDSA) and swap it in.
4. Persist the ledger to disk with `Append` writing a line at a time.
