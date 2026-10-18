package signertest_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/signertest"
)

func testKey(t *testing.T) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-signertest")))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// brokenSigner implements soroauth.Signer with a chosen defect. A conformance
// suite that no implementation fails is either perfect or checking nothing, so
// each defect below must be caught by name.
type brokenSigner struct {
	inner   soroauth.Signer
	address func() string
	sign    func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error)
}

func (b *brokenSigner) Address() string {
	if b.address != nil {
		return b.address()
	}
	return b.inner.Address()
}

func (b *brokenSigner) Sign(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	return b.sign(ctx, p, payload, b.inner)
}

func checksNamed(vs []signertest.Violation) string {
	names := make([]string, len(vs))
	for i, v := range vs {
		names[i] = v.Check
	}
	return strings.Join(names, ",")
}

func TestCheckPassesAConformingSigner(t *testing.T) {
	kp := testKey(t)
	var ops atomic.Int64
	counting := &brokenSigner{
		inner: soroauth.NewEd25519Signer(kp),
		sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
			if err := ctx.Err(); err != nil {
				return xdr.ScVal{}, err
			}
			ops.Add(1)
			return inner.Sign(ctx, p, payload)
		},
	}
	if vs := signertest.Check(context.Background(), signertest.Config{
		Signer: counting, Deterministic: true, SigningOperations: func() int { return int(ops.Load()) },
	}); len(vs) != 0 {
		t.Fatalf("a conforming signer was flagged: %v", vs)
	}
}

func TestCheckCatchesViolations(t *testing.T) {
	kp := testKey(t)
	good := soroauth.NewEd25519Signer(kp)

	var calls atomic.Int64
	var signed atomic.Int64

	tests := []struct {
		name   string
		signer soroauth.Signer
		cfg    func(*signertest.Config)
		want   string // check names that must appear
	}{
		{
			name:   "nil signer",
			signer: nil,
			want:   "signer",
		},
		{
			name: "ignores a cancelled context",
			signer: &brokenSigner{inner: good, sign: func(_ context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				return inner.Sign(context.Background(), p, payload)
			}},
			want: "cancelled_context_is_honoured",
		},
		{
			name: "signs before looking at the context",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				signed.Add(1)
				_, _ = inner.Sign(context.Background(), p, payload)
				return xdr.ScVal{}, ctx.Err()
			}},
			cfg:  func(c *signertest.Config) { c.SigningOperations = func() int { return int(signed.Load()) } },
			want: "cancelled_context_is_honoured",
		},
		{
			name: "returns a value together with an error",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				val, _ := inner.Sign(context.Background(), p, payload)
				return val, ctx.Err()
			}},
			want: "failure_returns_no_partial_value",
		},
		{
			name: "swallows the context error as a different error",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				if ctx.Err() != nil {
					return xdr.ScVal{}, soroauth.ErrMissingSigner
				}
				return inner.Sign(ctx, p, payload)
			}},
			want: "cancelled_context_is_honoured,expired_context_is_honoured",
		},
		{
			name: "mutates the preimage it was handed",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				p.SorobanAuthorization.Nonce++
				return inner.Sign(ctx, p, payload)
			}},
			want: "preimage_is_not_mutated",
		},
		{
			name: "address changes between calls",
			signer: &brokenSigner{inner: good,
				address: func() string {
					if calls.Add(1)%2 == 0 {
						return "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
					}
					return good.Address()
				},
				sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
					return inner.Sign(ctx, p, payload)
				}},
			want: "address_is_stable",
		},
		{
			name: "empty address",
			signer: &brokenSigner{inner: good, address: func() string { return "" }, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				return inner.Sign(ctx, p, payload)
			}},
			want: "address_is_stable",
		},
		{
			name: "returns Void",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				if err := ctx.Err(); err != nil {
					return xdr.ScVal{}, err
				}
				return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
			}},
			want: "sign_returns_a_signature",
		},
		{
			name: "ignores the payload while declared deterministic",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, _ [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				return inner.Sign(ctx, p, [32]byte{1})
			}},
			cfg:  func(c *signertest.Config) { c.Deterministic = true },
			want: "deterministic_contract",
		},
		{
			name: "varies between calls while declared deterministic",
			signer: &brokenSigner{inner: good, sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
				payload[0] ^= byte(calls.Add(1))
				return inner.Sign(ctx, p, payload)
			}},
			cfg:  func(c *signertest.Config) { c.Deterministic = true },
			want: "deterministic_contract",
		},
		{
			name:   "fails the caller's own verification",
			signer: good,
			cfg: func(c *signertest.Config) {
				c.Verify = func(xdr.ScVal, [32]byte) error { return soroauth.ErrSignatureMismatch }
			},
			want: "sign_returns_a_signature",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := signertest.Config{Signer: tt.signer}
			if tt.cfg != nil {
				tt.cfg(&cfg)
			}
			vs := signertest.Check(context.Background(), cfg)
			got := checksNamed(vs)
			for _, want := range strings.Split(tt.want, ",") {
				if !strings.Contains(got, want) {
					t.Fatalf("violations [%s] do not include %q: %v", got, want, vs)
				}
			}
		})
	}
}

func TestNonDeterministicSignersAreNotHeldToDeterminism(t *testing.T) {
	kp := testKey(t)
	var n atomic.Int64
	randomised := &brokenSigner{inner: soroauth.NewEd25519Signer(kp), sign: func(ctx context.Context, p xdr.HashIdPreimage, payload [32]byte, inner soroauth.Signer) (xdr.ScVal, error) {
		payload[0] ^= byte(n.Add(1))
		return inner.Sign(ctx, p, payload)
	}}
	if vs := signertest.Check(context.Background(), signertest.Config{Signer: randomised}); len(vs) != 0 {
		t.Fatalf("a non-deterministic signer was flagged for determinism it never claimed: %v", vs)
	}
}

func TestRunPassesAConformingSigner(t *testing.T) {
	signertest.Run(t, signertest.Config{Signer: soroauth.NewEd25519Signer(testKey(t)), Deterministic: true})
}
