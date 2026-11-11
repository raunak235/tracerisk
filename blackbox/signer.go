package blackbox

import (
	"crypto/ed25519"
	"crypto/rand"
)

type Signer interface {
	Sign(msg []byte) []byte
	PublicKey() ed25519.PublicKey
}

type Ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewEd25519Signer() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{priv: priv, pub: pub}, nil
}

func (s *Ed25519Signer) Sign(msg []byte) []byte       { return ed25519.Sign(s.priv, msg) }
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey { return s.pub }

var _ Signer = (*Ed25519Signer)(nil)
