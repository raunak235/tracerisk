# TraceRisk: a tamper-evident black box for AI agents (Go)

OOP + Cryptography project. A working prototype of the TraceRisk startup idea:

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

## OOP concepts (and where to find them)

Go has no `class` keyword. It does OOP with **structs + methods + interfaces + embedding**.

| Concept | Where | How |
|---|---|---|
| **Encapsulation** | `blackbox/ledger.go`, `signer.go` | `Ledger.events` and `Ed25519Signer.priv` are lowercase (private). The only way in is `Append()`; `Events()` returns a *copy* (see `TestEventsReturnsCopy`). |
| **Abstraction / Interface** | `agent.Agent`, `blackbox.Signer`, `risk.Scorer` | Callers depend on *what* something does, not *how*. |
| **Inheritance (via embedding)** | `agent/agent.go` | `DevOpsAgent`, `RefundAgent`, `RobotAgent` each embed `Base` and get `ID()` / `Kind()` for free. Go prefers *composition over inheritance*. |
| **Polymorphism** | `main.go` | `agents := []agent.Agent{...}`, then `a.Act(step)`: same call, three behaviours. |
| **Strategy pattern** | `risk/risk.go` | Swap `FrequencyScorer`, `SeverityScorer`, `ExposureScorer` freely. |
| **Composite pattern** | `risk.Composite` | Holds many `Scorer`s *and is itself a `Scorer`*, so models can nest. |
| **Custom error type** | `blackbox.TamperError` | Carries `Index` + `Reason`, not just a string. |
| **Method chaining** | `NewComposite().Add(..).Add(..)` | `Add` returns the receiver. |
| **Compile-time interface check** | `var _ Agent = (*DevOpsAgent)(nil)` | Compiler fails if a type stops satisfying the interface. |

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

## Likely viva questions

**Why Go if it has no classes?** Go uses composition and interfaces. Embedding gives code reuse; interfaces give polymorphism, and they are satisfied implicitly (no `implements` keyword).

**Why hash AND sign? Isn't the hash enough?** Anyone can recompute SHA-256. A hash proves *consistency*; a signature proves *who wrote it*.

**Why a Merkle tree?** One 32-byte fingerprint of the whole log. It can be published, and a regulator can later detect rewrites or truncation.

**Why is `ComputeHash` exported?** On purpose, to show the attacker knows the algorithm and still fails (Attack C). Security comes from the private key, not from hiding the algorithm.

**Why does `Events()` copy the slice?** Otherwise callers could mutate the ledger's internals and break encapsulation.

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
