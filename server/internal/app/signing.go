package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Each organization has its own trust anchor. The root secret never signs a
// delivered policy, so a valid policy from another tenant cannot pass its pin.
func (a *App) policyKey(organization string) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	reader := hkdf.New(sha256.New, a.config.SigningKey.Seed(), []byte(organization), []byte("milvago/policy/v1"))
	if _, e := io.ReadFull(reader, seed); e != nil {
		panic(e)
	}
	return ed25519.NewKeyFromSeed(seed)
}
