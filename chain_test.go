package soroauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// scriptedSigner is a Signer whose behaviour a test writes out, and which
// counts how often it was called.
type scriptedSigner struct {
	address string
	value   xdr.ScVal
	err     error
	calls   int
	onSign  func()
}

func (s *scriptedSigner) Address() string { return s.address }
func (s *scriptedSigner) Sign(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
	s.calls++
	if s.onSign != nil {
		s.onSign()
	}
	if s.err != nil {
		return xdr.ScVal{}, s.err
	}
	return s.value, nil
}

func chainTestKey(t *testing.T) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-chain-test")))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func sigValue(b byte) xdr.ScVal { return scBytes([]byte{b}) }

func newScripted(addr string, v xdr.ScVal, err error) *scriptedSigner {
	return &scriptedSigner{address: addr, value: v, err: err}
}

func chainAttempts(t *testing.T, err error) []ChainAttempt {
	t.Helper()
	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *ChainError", err)
	}
	return ce.Attempts
}

func TestFallbackSigner(t *testing.T) {
	addr := chainTestKey(t).Address()
	timeout := MarkTransient(errors.New("kms timeout"))

	t.Run("first success wins and the rest are recorded as skipped", func(t *testing.T) {
		a, b := newScripted(addr, sigValue(1), nil), newScripted(addr, sigValue(2), nil)
		var audit []ChainAttempt
		chain, err := NewFallbackSigner([]Signer{a, b}, WithChainAudit(func(x ChainAttempt) { audit = append(audit, x) }))
		if err != nil {
			t.Fatal(err)
		}
		got, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if err != nil || got.Type != xdr.ScValTypeScvBytes || (*got.Bytes)[0] != 1 {
			t.Fatalf("got %v, %v; want signer 0's value", got, err)
		}
		if b.calls != 0 {
			t.Fatalf("signer 1 was called %d times after signer 0 succeeded", b.calls)
		}
		if len(audit) != 2 || audit[0].Outcome != ChainSucceeded || audit[1].Outcome != ChainSkipped {
			t.Fatalf("audit = %+v", audit)
		}
	})

	t.Run("a transient failure falls through to the next signer", func(t *testing.T) {
		a, b := newScripted(addr, xdr.ScVal{}, timeout), newScripted(addr, sigValue(2), nil)
		var audit []ChainAttempt
		chain, _ := NewFallbackSigner([]Signer{a, b}, WithChainAudit(func(x ChainAttempt) { audit = append(audit, x) }))
		got, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if err != nil || (*got.Bytes)[0] != 2 {
			t.Fatalf("got %v, %v", got, err)
		}
		if len(audit) != 2 || audit[0].Outcome != ChainTransientFailure || audit[0].Err == nil || audit[1].Outcome != ChainSucceeded {
			t.Fatalf("audit = %+v", audit)
		}
	})

	t.Run("a policy refusal stops the chain and never reaches the backup", func(t *testing.T) {
		refusal := fmt.Errorf("limit exceeded: %w", ErrPolicyRefusal)
		a, b := newScripted(addr, xdr.ScVal{}, refusal), newScripted(addr, sigValue(2), nil)
		var audit []ChainAttempt
		chain, _ := NewFallbackSigner([]Signer{a, b}, WithChainAudit(func(x ChainAttempt) { audit = append(audit, x) }))
		got, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if !errors.Is(err, ErrPolicyRefusal) {
			t.Fatalf("err = %v, want ErrPolicyRefusal", err)
		}
		if got.Type != 0 || got.Bytes != nil {
			t.Fatalf("a refused chain returned a value: %v", got)
		}
		if b.calls != 0 {
			t.Fatalf("the backup was asked %d times after a policy refusal", b.calls)
		}
		attempts := chainAttempts(t, err)
		if attempts[0].Outcome != ChainTerminalFailure || attempts[1].Outcome != ChainSkipped {
			t.Fatalf("attempts = %+v", attempts)
		}
		if len(audit) != 2 {
			t.Fatalf("audit sink saw %d attempts, want 2", len(audit))
		}
	})

	t.Run("a refusal marked transient is still terminal", func(t *testing.T) {
		both := MarkTransient(fmt.Errorf("denied: %w", ErrPolicyRefusal))
		a, b := newScripted(addr, xdr.ScVal{}, both), newScripted(addr, sigValue(2), nil)
		chain, _ := NewFallbackSigner([]Signer{a, b})
		_, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if !errors.Is(err, ErrPolicyRefusal) || b.calls != 0 {
			t.Fatalf("err = %v, backup calls = %d", err, b.calls)
		}
	})

	t.Run("a signature rejection is terminal", func(t *testing.T) {
		a, b := newScripted(addr, xdr.ScVal{}, ErrSignatureMismatch), newScripted(addr, sigValue(2), nil)
		chain, _ := NewFallbackSigner([]Signer{a, b})
		_, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if !errors.Is(err, ErrSignatureMismatch) || b.calls != 0 {
			t.Fatalf("err = %v, backup calls = %d", err, b.calls)
		}
	})

	t.Run("an unclassified error is terminal", func(t *testing.T) {
		a, b := newScripted(addr, xdr.ScVal{}, errors.New("something unexpected")), newScripted(addr, sigValue(2), nil)
		chain, _ := NewFallbackSigner([]Signer{a, b})
		_, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if err == nil || b.calls != 0 {
			t.Fatalf("err = %v, backup calls = %d", err, b.calls)
		}
		if errors.Is(err, ErrChainExhausted) {
			t.Fatal("an unclassified error was reported as exhaustion")
		}
	})

	t.Run("every signer failing transiently is exhaustion", func(t *testing.T) {
		a, b := newScripted(addr, xdr.ScVal{}, timeout), newScripted(addr, xdr.ScVal{}, timeout)
		chain, _ := NewFallbackSigner([]Signer{a, b})
		_, err := chain.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		if !errors.Is(err, ErrChainExhausted) {
			t.Fatalf("err = %v, want ErrChainExhausted", err)
		}
		if got := len(chainAttempts(t, err)); got != 2 {
			t.Fatalf("%d attempts recorded, want 2", got)
		}
	})

	t.Run("cancellation during a signer stops the chain before the next one", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		a := newScripted(addr, xdr.ScVal{}, timeout)
		a.onSign = cancel
		b := newScripted(addr, sigValue(2), nil)
		chain, _ := NewFallbackSigner([]Signer{a, b})
		_, err := chain.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if b.calls != 0 {
			t.Fatalf("signer 1 was called %d times after cancellation", b.calls)
		}
		attempts := chainAttempts(t, err)
		if attempts[1].Outcome != ChainSkipped {
			t.Fatalf("attempts = %+v", attempts)
		}
	})

	t.Run("an already-cancelled context calls no signer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a, b := newScripted(addr, sigValue(1), nil), newScripted(addr, sigValue(2), nil)
		chain, _ := NewFallbackSigner([]Signer{a, b})
		_, err := chain.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
		if !errors.Is(err, context.Canceled) || a.calls+b.calls != 0 {
			t.Fatalf("err = %v, calls = %d", err, a.calls+b.calls)
		}
	})
}

func TestNewChainRejectsBadInput(t *testing.T) {
	addr := chainTestKey(t).Address()
	other, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-chain-other")))
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *scriptedSigner

	tests := []struct {
		name    string
		build   func() (Signer, error)
		wantErr error
	}{
		{"no signers", func() (Signer, error) { return NewFallbackSigner(nil) }, ErrMissingSigner},
		{"nil signer", func() (Signer, error) { return NewFallbackSigner([]Signer{nil}) }, ErrMissingSigner},
		{"typed nil signer", func() (Signer, error) { return NewFallbackSigner([]Signer{typedNil}) }, ErrMissingSigner},
		{"empty address", func() (Signer, error) { return NewFallbackSigner([]Signer{newScripted("", sigValue(1), nil)}) }, ErrMissingSigner},
		{"backup for another account", func() (Signer, error) {
			return NewFallbackSigner([]Signer{newScripted(addr, sigValue(1), nil), newScripted(other.Address(), sigValue(1), nil)})
		}, ErrSignerAddressMismatch},
		{"quorum of zero", func() (Signer, error) { return NewQuorumSigner(0, []Signer{newScripted(addr, sigValue(1), nil)}) }, ErrMissingSigner},
		{"quorum above the signers", func() (Signer, error) { return NewQuorumSigner(2, []Signer{newScripted(addr, sigValue(1), nil)}) }, ErrMissingSigner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.build()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if s != nil {
				t.Fatal("a signer was returned with an error")
			}
		})
	}
}

func TestMarkTransient(t *testing.T) {
	if MarkTransient(nil) != nil {
		t.Fatal("MarkTransient(nil) is not nil")
	}
	base := errors.New("boom")
	marked := MarkTransient(base)
	if !errors.Is(marked, ErrSignerTransient) || !errors.Is(marked, base) || marked.Error() != "boom" {
		t.Fatalf("marked = %v", marked)
	}
}

func TestQuorumSigner(t *testing.T) {
	addr := chainTestKey(t).Address()
	timeout := MarkTransient(errors.New("hsm timeout"))
	sign := func(c Signer, ctx context.Context) (xdr.ScVal, error) {
		return c.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
	}

	t.Run("agreeing signers reach the quorum and the rest are not asked", func(t *testing.T) {
		a, b, c := newScripted(addr, sigValue(1), nil), newScripted(addr, sigValue(1), nil), newScripted(addr, sigValue(9), nil)
		var audit []ChainAttempt
		chain, _ := NewQuorumSigner(2, []Signer{a, b, c}, WithChainAudit(func(x ChainAttempt) { audit = append(audit, x) }))
		got, err := sign(chain, context.Background())
		if err != nil || (*got.Bytes)[0] != 1 {
			t.Fatalf("got %v, %v", got, err)
		}
		if c.calls != 0 {
			t.Fatal("a signer was asked after the quorum was reached")
		}
		if len(audit) != 3 || audit[2].Outcome != ChainSkipped {
			t.Fatalf("audit = %+v", audit)
		}
	})

	t.Run("disagreement is a refusal that names the signers, even with a majority", func(t *testing.T) {
		a, b, c := newScripted(addr, sigValue(1), nil), newScripted(addr, sigValue(2), nil), newScripted(addr, sigValue(1), nil)
		chain, _ := NewQuorumSigner(2, []Signer{a, b, c})
		got, err := sign(chain, context.Background())
		if !errors.Is(err, ErrQuorumDisagreement) {
			t.Fatalf("err = %v, want ErrQuorumDisagreement", err)
		}
		if got.Type != 0 || got.Bytes != nil {
			t.Fatal("a disagreeing quorum returned a value")
		}
		const want = "signers [0] returned one signature and signer 1 another"
		if msg := err.Error(); !contains(msg, want) {
			t.Fatalf("error %q does not name the signers (%q)", msg, want)
		}
		if c.calls != 0 {
			t.Fatal("the chain kept asking after a disagreement")
		}
	})

	t.Run("a transient failure is tolerated while the quorum is reachable", func(t *testing.T) {
		a, b, c := newScripted(addr, xdr.ScVal{}, timeout), newScripted(addr, sigValue(1), nil), newScripted(addr, sigValue(1), nil)
		chain, _ := NewQuorumSigner(2, []Signer{a, b, c})
		if _, err := sign(chain, context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("too few signatures is not-met", func(t *testing.T) {
		a, b, c := newScripted(addr, xdr.ScVal{}, timeout), newScripted(addr, sigValue(1), nil), newScripted(addr, xdr.ScVal{}, timeout)
		chain, _ := NewQuorumSigner(2, []Signer{a, b, c})
		_, err := sign(chain, context.Background())
		if !errors.Is(err, ErrQuorumNotMet) {
			t.Fatalf("err = %v, want ErrQuorumNotMet", err)
		}
	})

	t.Run("an unreachable quorum stops asking", func(t *testing.T) {
		a, b, c := newScripted(addr, xdr.ScVal{}, timeout), newScripted(addr, xdr.ScVal{}, timeout), newScripted(addr, sigValue(1), nil)
		chain, _ := NewQuorumSigner(2, []Signer{a, b, c})
		_, err := sign(chain, context.Background())
		if !errors.Is(err, ErrQuorumNotMet) || c.calls != 0 {
			t.Fatalf("err = %v, last signer calls = %d", err, c.calls)
		}
	})

	t.Run("a policy refusal abandons the quorum", func(t *testing.T) {
		a, b := newScripted(addr, sigValue(1), nil), newScripted(addr, xdr.ScVal{}, fmt.Errorf("no: %w", ErrPolicyRefusal))
		c := newScripted(addr, sigValue(1), nil)
		chain, _ := NewQuorumSigner(2, []Signer{a, b, c})
		_, err := sign(chain, context.Background())
		if !errors.Is(err, ErrPolicyRefusal) || c.calls != 0 {
			t.Fatalf("err = %v, last signer calls = %d", err, c.calls)
		}
	})

	t.Run("cancellation stops the quorum before the next signer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		a := newScripted(addr, sigValue(1), nil)
		a.onSign = cancel
		b := newScripted(addr, sigValue(1), nil)
		chain, _ := NewQuorumSigner(2, []Signer{a, b})
		_, err := sign(chain, ctx)
		if !errors.Is(err, context.Canceled) || b.calls != 0 {
			t.Fatalf("err = %v, signer 1 calls = %d", err, b.calls)
		}
	})

	t.Run("real ed25519 signers over one key agree", func(t *testing.T) {
		kp := chainTestKey(t)
		chain, err := NewQuorumSigner(2, []Signer{NewEd25519Signer(kp), NewEd25519Signer(kp)})
		if err != nil {
			t.Fatal(err)
		}
		got, err := sign(chain, context.Background())
		if err != nil || got.Type != xdr.ScValTypeScvVec {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
