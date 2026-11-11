package blackbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type TamperError struct {
	Index  int
	Reason string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("tamper detected at event #%d: %s", e.Index, e.Reason)
}

func Verify(events []Event, pub ed25519.PublicKey) error {
	prev := GenesisHash
	for i, e := range events {
		if e.Index != i {
			return &TamperError{i, fmt.Sprintf("sequence broken (expected #%d, found #%d) - event deleted or reordered", i, e.Index)}
		}
		if ComputeHash(e) != e.Hash {
			return &TamperError{i, "content was changed after logging (hash mismatch)"}
		}
		if e.PrevHash != prev {
			return &TamperError{i, "link to previous event is broken (chain mismatch)"}
		}
		sig, err := hex.DecodeString(e.Signature)
		if err != nil || !ed25519.Verify(pub, []byte(e.Hash), sig) {
			return &TamperError{i, "signature invalid - not produced by the logger's private key"}
		}
		prev = e.Hash
	}
	return nil
}

func MerkleRoot(events []Event) string {
	if len(events) == 0 {
		return GenesisHash
	}
	level := make([][]byte, len(events))
	for i, e := range events {
		sum := sha256.Sum256([]byte(e.Hash))
		level[i] = sum[:]
	}
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			sum := sha256.Sum256(append(append([]byte{}, level[i]...), right...))
			next = append(next, sum[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

func VerifyAnchor(events []Event, publishedRoot string) error {
	if got := MerkleRoot(events); got != publishedRoot {
		return fmt.Errorf("merkle root mismatch: log truncated or rewritten (got %s..., published %s...)", got[:12], publishedRoot[:12])
	}
	return nil
}
