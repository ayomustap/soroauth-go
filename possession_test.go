package soroauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func possessionKey(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestCheckPossession(t *testing.T) {
	a, b := possessionKey(t, "soroauth-possession-a"), possessionKey(t, "soroauth-possession-b")
	ctx := context.Background()

	// A signer that claims a's address but holds b's key: the misconfiguration
	// this check exists to find.
	wrongKey := SignerFunc(a.Address(), NewEd25519Signer(b).Sign)
	multi, err := NewAccountMultiSigner(a.Address(), b)
	if err != nil {
		t.Fatal(err)
	}
	contract := "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"

	tests := []struct {
		name    string
		signer  Signer
		opts    []PossessionOption
		want    VerifyVerdict
		reason  string
		wantErr error
	}{
		{"key controls its address", NewEd25519Signer(a), nil, VerdictVerified, "", nil},
		{"signer holds a different key than its address", wrongKey, nil, VerdictInvalid, "does not match its configured address", nil},
		{"multisig account with only foreign keys is not a pass", multi, nil, VerdictInvalid, "AllowAccountSigningKeys", nil},
		{"multisig account with foreign keys declared is cannot_check", multi, []PossessionOption{AllowAccountSigningKeys()}, VerdictCannotCheck, "on-chain", nil},
		{"contract address cannot be checked offline", SignerFunc(contract, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return scVec(), nil
		}), nil, VerdictCannotCheck, "__check_auth", nil},
		{"an unreadable signature shape is cannot_check, not a pass", SignerFunc(a.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return scBytes([]byte("opaque")), nil
		}), nil, VerdictCannotCheck, "cannot be checked offline", nil},
		{"an unsigned result is invalid", SignerFunc(a.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
		}), nil, VerdictInvalid, "no signature", nil},
		{"a forged signature is invalid", SignerFunc(a.Address(), func(_ context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
			raw, _ := rawEd25519Key(a.Address())
			return Ed25519SignatureScVal(raw, make([]byte, 64))
		}), nil, VerdictInvalid, "does not control", nil},
		{"a nil signer", nil, nil, "", "", ErrMissingSigner},
		{"a signer that fails", SignerFunc(a.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return xdr.ScVal{}, ErrPolicyRefusal
		}), nil, "", "", ErrPolicyRefusal},
		{"an address that is not an address", SignerFunc("not-an-address", nil), nil, "", "", ErrMissingSigner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := CheckPossession(ctx, tt.signer, tt.opts...)
			if tt.wantErr != nil {
				if tt.name == "an address that is not an address" {
					if err == nil {
						t.Fatal("no error for an unparseable address")
					}
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != tt.want {
				t.Fatalf("verdict = %q (%s), want %q", report.Verdict, report.Reason, tt.want)
			}
			if !strings.Contains(report.Reason, tt.reason) {
				t.Fatalf("reason %q does not contain %q", report.Reason, tt.reason)
			}
			if report.Passed() != (tt.want == VerdictVerified) {
				t.Fatalf("Passed() = %v for verdict %q", report.Passed(), report.Verdict)
			}
		})
	}
}

// TestPossessionPayloadIsNotAnAuthorization proves the property the doc comment
// claims: the signed payload is not the payload of any entry on a real
// network, so the signature cannot be replayed as one.
func TestPossessionPayloadIsNotAnAuthorization(t *testing.T) {
	preimage, payload, err := possessionPreimage()
	if err != nil {
		t.Fatal(err)
	}
	sa := preimage.SorobanAuthorization
	if sa == nil || sa.NetworkId != network.ID(possessionNetworkPassphrase) {
		t.Fatal("the preimage is not bound to the possession network")
	}
	for name, passphrase := range map[string]string{"testnet": network.TestNetworkPassphrase, "public": network.PublicNetworkPassphrase} {
		real := *preimage.SorobanAuthorization
		real.NetworkId = network.ID(passphrase)
		realPayload, err := Payload(xdr.HashIdPreimage{Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization, SorobanAuthorization: &real})
		if err != nil {
			t.Fatal(err)
		}
		if realPayload == payload {
			t.Fatalf("the possession payload equals the %s payload for the same invocation", name)
		}
	}

	_, again, err := possessionPreimage()
	if err != nil {
		t.Fatal(err)
	}
	if again == payload {
		t.Fatal("two possession checks signed the same payload; the nonce is not random")
	}
}
