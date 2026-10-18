package soroauth_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/signertest"
)

func conformanceKey(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// verifyAccountSignature checks a built-in classic account signature, so the
// conformance run also proves the shipped signers' output is valid and not
// merely well-behaved.
func verifyAccountSignature(signature xdr.ScVal, payload [32]byte) error {
	if signature.Type != xdr.ScValTypeScvVec || signature.Vec == nil || *signature.Vec == nil {
		return fmt.Errorf("signature is %s, not a vector", signature.Type)
	}
	for i, element := range **signature.Vec {
		if element.Type != xdr.ScValTypeScvMap || element.Map == nil || *element.Map == nil {
			return fmt.Errorf("element %d is not a map", i)
		}
		var pub, sig []byte
		for _, entry := range **element.Map {
			if entry.Key.Sym == nil || entry.Val.Bytes == nil {
				continue
			}
			switch string(*entry.Key.Sym) {
			case "public_key":
				pub = *entry.Val.Bytes
			case "signature":
				sig = *entry.Val.Bytes
			}
		}
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, payload[:], sig) {
			return fmt.Errorf("signature %d does not verify", i)
		}
	}
	return nil
}

// TestShippedSignersConform runs every Signer this package ships through the
// conformance suite.
func TestShippedSignersConform(t *testing.T) {
	a, b := conformanceKey(t, "soroauth-conformance-a"), conformanceKey(t, "soroauth-conformance-b")

	multi, err := soroauth.NewAccountMultiSigner(a.Address(), a, b)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := soroauth.NewFallbackSigner([]soroauth.Signer{soroauth.NewEd25519Signer(a), soroauth.NewEd25519Signer(a)})
	if err != nil {
		t.Fatal(err)
	}
	quorum, err := soroauth.NewQuorumSigner(2, []soroauth.Signer{soroauth.NewEd25519Signer(a), soroauth.NewEd25519Signer(a)})
	if err != nil {
		t.Fatal(err)
	}
	ed := soroauth.NewEd25519Signer(a)
	viaFunc := soroauth.SignerFunc(a.Address(), ed.Sign)

	tests := []struct {
		name   string
		signer soroauth.Signer
	}{
		{"ed25519", ed},
		{"account multisig", multi},
		{"signer func", viaFunc},
		{"retry wrapper", soroauth.WithRetry(ed, soroauth.RetryConfig{Attempts: 2})},
		{"fallback chain", fallback},
		{"quorum chain", quorum},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signertest.Run(t, signertest.Config{
				Signer:        tt.signer,
				Deterministic: true,
				Verify:        verifyAccountSignature,
			})
		})
	}
}
