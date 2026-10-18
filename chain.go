package soroauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// A signer chain combines several Signers for one address under a rule that
// is declared up front: take the first that succeeds (NewFallbackSigner), or
// require N of them to return the same signature (NewQuorumSigner).
//
// The hard part is the error taxonomy. Falling through to a backup is only
// safe when "this signer could not answer" can be told apart from "this signer
// answered no". The version that is easy to write falls through on any error,
// which turns a policy refusal into a request to ask someone else. So the
// classification is fixed here, and it fails closed:
//
//   - a failure wrapping ErrSignerTransient is transient: the chain may move
//     on. MarkTransient is how a signer, or the code wrapping it, says so;
//   - a failure wrapping ErrPolicyRefusal, or any rejection IsSignatureRejection
//     recognises, is terminal even if it is also marked transient;
//   - every other error is terminal. A chain that cannot classify an error
//     stops, because guessing "probably a timeout" is how a refusal gets
//     routed around.
//
// The two chains are not the same thing as AccountMultiSigner. That combines
// different keys of one classic account into one multi-signature vector
// (the host needs them all). A chain combines interchangeable signers for one
// credential: a primary KMS and a backup HSM holding the same key, or
// replicas whose answers are cross-checked. A quorum needs byte-identical
// signatures, which ed25519 gives for the same key and message; a signer whose
// signatures are randomised (ECDSA) will never agree with itself, so a quorum
// over those always disagrees and is refused, never silently resolved.

// MarkTransient marks err as a failure another signer could reasonably clear,
// such as a timeout or an unreachable service. The result matches
// ErrSignerTransient and still unwraps to err. A nil error stays nil.
func MarkTransient(err error) error {
	if err == nil {
		return nil
	}
	return &transientError{err: err}
}

type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() []error {
	return []error{ErrSignerTransient, e.err}
}

// ChainOutcome is what happened to one signer in a chain.
type ChainOutcome string

const (
	// ChainSucceeded: the signer returned a signature.
	ChainSucceeded ChainOutcome = "succeeded"
	// ChainTransientFailure: the signer failed in a way the chain may move on from.
	ChainTransientFailure ChainOutcome = "transient_failure"
	// ChainTerminalFailure: the signer failed in a way that stops the chain.
	ChainTerminalFailure ChainOutcome = "terminal_failure"
	// ChainSkipped: the signer was never called. Reason says why.
	ChainSkipped ChainOutcome = "skipped"
)

// ChainAttempt is the audit record of one signer in a chain. Every signer
// produces exactly one per Sign call, including those that were skipped, so
// the record shows what was not asked as well as what was.
type ChainAttempt struct {
	// Index is the signer's position in the chain.
	Index int
	// Address is the address the chain signs for.
	Address string
	Outcome ChainOutcome
	// Reason is a plain-language account of the outcome.
	Reason string
	// Err is the signer's error for a failed attempt, nil otherwise.
	Err error
}

// ChainError is returned when a chain does not produce a signature. It carries
// the full audit record of the call and unwraps to the cause, so errors.Is
// matches ErrPolicyRefusal, ErrChainExhausted, ErrQuorumNotMet,
// ErrQuorumDisagreement or a context error.
type ChainError struct {
	Attempts []ChainAttempt
	cause    error
}

// Error returns the cause's message.
func (e *ChainError) Error() string { return e.cause.Error() }

// Unwrap returns the cause, so errors.Is sees the sentinel.
func (e *ChainError) Unwrap() error { return e.cause }

// ChainOption configures a chain.
type ChainOption func(*chainConfig)

type chainConfig struct {
	audit func(ChainAttempt)
}

// WithChainAudit registers a function called with each ChainAttempt as it is
// decided, including skipped signers. It is called synchronously from Sign,
// must not block, and must not retain or mutate the error. The chain never
// logs; this is how an operator gets the record into their own log.
func WithChainAudit(fn func(ChainAttempt)) ChainOption {
	return func(c *chainConfig) { c.audit = fn }
}

type chainSigner struct {
	address string
	signers []Signer
	quorum  int // 0 means fallback
	cfg     chainConfig
}

// NewFallbackSigner returns a Signer that tries signers in order and returns
// the first signature. It moves to the next signer only after a transient
// failure (see ErrSignerTransient); a policy refusal or any unclassified error
// stops the chain at once, and a cancelled context stops it before any further
// signer is called. When every signer fails transiently it returns
// ErrChainExhausted.
//
// Every signer must report the same, non-empty Address: a backup that signs
// for a different account would produce a signature that fails on-chain after
// fees are paid.
func NewFallbackSigner(signers []Signer, opts ...ChainOption) (Signer, error) {
	return newChain(0, signers, opts)
}

// NewQuorumSigner returns a Signer that requires quorum signers to return the
// same signature. Signers are asked in order. Two different signatures from any
// two signers are a refusal (ErrQuorumDisagreement) naming the signers on each
// side, never a pick, even if a majority exists. When quorum identical
// signatures are in hand the remaining signers are not called. A terminal
// failure stops the chain; a transient one is tolerated while the quorum is
// still reachable, after which the result is ErrQuorumNotMet.
//
// 1 <= quorum <= len(signers). Every signer must report the same, non-empty
// Address.
func NewQuorumSigner(quorum int, signers []Signer, opts ...ChainOption) (Signer, error) {
	if quorum < 1 || quorum > len(signers) {
		return nil, fmt.Errorf("soroauth: new quorum signer: quorum %d is outside 1..%d: %w",
			quorum, len(signers), ErrMissingSigner)
	}
	return newChain(quorum, signers, opts)
}

func newChain(quorum int, signers []Signer, opts []ChainOption) (Signer, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("soroauth: new signer chain: no signers: %w", ErrMissingSigner)
	}
	address := ""
	for i, s := range signers {
		if isNilSigner(s) {
			return nil, fmt.Errorf("soroauth: new signer chain: signer %d is nil: %w", i, ErrMissingSigner)
		}
		a := s.Address()
		if a == "" {
			return nil, fmt.Errorf("soroauth: new signer chain: signer %d has an empty address: %w", i, ErrMissingSigner)
		}
		if i == 0 {
			address = a
		} else if a != address {
			return nil, fmt.Errorf("soroauth: new signer chain: signer %d is for %s, signer 0 is for %s: %w",
				i, a, address, ErrSignerAddressMismatch)
		}
	}
	c := &chainSigner{address: address, signers: append([]Signer(nil), signers...), quorum: quorum}
	for _, opt := range opts {
		if opt != nil {
			opt(&c.cfg)
		}
	}
	return c, nil
}

func (c *chainSigner) Address() string { return c.address }

func (c *chainSigner) record(attempts *[]ChainAttempt, a ChainAttempt) {
	a.Address = c.address
	*attempts = append(*attempts, a)
	if c.cfg.audit != nil {
		c.cfg.audit(a)
	}
}

// skipFrom records every signer from index i onward as skipped.
func (c *chainSigner) skipFrom(attempts *[]ChainAttempt, i int, reason string) {
	for ; i < len(c.signers); i++ {
		c.record(attempts, ChainAttempt{Index: i, Outcome: ChainSkipped, Reason: reason})
	}
}

func (c *chainSigner) fail(attempts []ChainAttempt, cause error) (xdr.ScVal, error) {
	return xdr.ScVal{}, &ChainError{Attempts: attempts, cause: cause}
}

func (c *chainSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if c.quorum > 0 {
		return c.signQuorum(ctx, preimage, payload)
	}
	return c.signFallback(ctx, preimage, payload)
}

// classify decides whether a signer's failure lets the chain continue. Terminal
// wins over transient, and anything unmarked is terminal.
func classify(err error) ChainOutcome {
	if errors.Is(err, ErrPolicyRefusal) || IsSignatureRejection(err) {
		return ChainTerminalFailure
	}
	if errors.Is(err, ErrSignerTransient) {
		return ChainTransientFailure
	}
	return ChainTerminalFailure
}

func (c *chainSigner) signFallback(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	var attempts []ChainAttempt
	for i, s := range c.signers {
		if err := ctx.Err(); err != nil {
			c.skipFrom(&attempts, i, "context cancelled before this signer was called")
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer chain: %w", err))
		}
		val, err := s.Sign(ctx, preimage, payload)
		if err == nil {
			c.record(&attempts, ChainAttempt{Index: i, Outcome: ChainSucceeded, Reason: "returned a signature"})
			c.skipFrom(&attempts, i+1, fmt.Sprintf("signer %d succeeded", i))
			return val, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			c.record(&attempts, ChainAttempt{Index: i, Outcome: ChainTerminalFailure, Reason: "context cancelled during signing", Err: err})
			c.skipFrom(&attempts, i+1, "context cancelled")
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer chain: %w", ctxErr))
		}
		outcome := classify(err)
		if outcome == ChainTerminalFailure {
			c.record(&attempts, ChainAttempt{Index: i, Outcome: outcome, Err: err,
				Reason: "terminal failure; the chain does not fall through: " + terminalReason(err)})
			c.skipFrom(&attempts, i+1, fmt.Sprintf("signer %d failed terminally", i))
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer chain: signer %d: %w", i, err))
		}
		c.record(&attempts, ChainAttempt{Index: i, Outcome: outcome, Err: err, Reason: "transient failure; trying the next signer"})
	}
	return c.fail(attempts, fmt.Errorf("soroauth: sign signer chain: %d signers: %w", len(c.signers), ErrChainExhausted))
}

// terminalReason says why an error stopped the chain.
func terminalReason(err error) string {
	switch {
	case errors.Is(err, ErrPolicyRefusal):
		return "policy refusal"
	case IsSignatureRejection(err):
		return "signature rejection"
	default:
		return "error not marked transient"
	}
}

func (c *chainSigner) signQuorum(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	var attempts []ChainAttempt
	var agreed xdr.ScVal
	var agreedBytes []byte
	var agreedBy []int

	for i, s := range c.signers {
		if err := ctx.Err(); err != nil {
			c.skipFrom(&attempts, i, "context cancelled before this signer was called")
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: %w", err))
		}
		// If the quorum can no longer be reached, asking more signers only
		// spends their time.
		if len(agreedBy)+(len(c.signers)-i) < c.quorum {
			c.skipFrom(&attempts, i, "quorum can no longer be reached")
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: %d of %d required, %d agreed: %w",
				c.quorum, len(c.signers), len(agreedBy), ErrQuorumNotMet))
		}

		val, err := s.Sign(ctx, preimage, payload)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				c.record(&attempts, ChainAttempt{Index: i, Outcome: ChainTerminalFailure, Reason: "context cancelled during signing", Err: err})
				c.skipFrom(&attempts, i+1, "context cancelled")
				return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: %w", ctxErr))
			}
			outcome := classify(err)
			if outcome == ChainTerminalFailure {
				c.record(&attempts, ChainAttempt{Index: i, Outcome: outcome, Err: err,
					Reason: "terminal failure; the quorum is abandoned: " + terminalReason(err)})
				c.skipFrom(&attempts, i+1, fmt.Sprintf("signer %d failed terminally", i))
				return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: signer %d: %w", i, err))
			}
			c.record(&attempts, ChainAttempt{Index: i, Outcome: outcome, Err: err, Reason: "transient failure; the quorum may still be reached"})
			continue
		}

		encoded, err := val.MarshalBinary()
		if err != nil {
			c.record(&attempts, ChainAttempt{Index: i, Outcome: ChainTerminalFailure, Err: err, Reason: "signature is not encodable"})
			c.skipFrom(&attempts, i+1, fmt.Sprintf("signer %d returned an unencodable signature", i))
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: signer %d: %w", i, err))
		}
		if agreedBy != nil && !bytes.Equal(encoded, agreedBytes) {
			c.record(&attempts, ChainAttempt{Index: i, Outcome: ChainTerminalFailure, Reason: "returned a different signature from the signers before it"})
			c.skipFrom(&attempts, i+1, "signers disagree")
			return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: signers %s returned one signature and signer %d another: %w",
				joinIndexes(agreedBy), i, ErrQuorumDisagreement))
		}
		c.record(&attempts, ChainAttempt{Index: i, Outcome: ChainSucceeded, Reason: "returned a signature"})
		agreed, agreedBytes = val, encoded
		agreedBy = append(agreedBy, i)

		if len(agreedBy) == c.quorum {
			c.skipFrom(&attempts, i+1, "quorum reached")
			return agreed, nil
		}
	}
	return c.fail(attempts, fmt.Errorf("soroauth: sign signer quorum: %d of %d required, %d agreed: %w",
		c.quorum, len(c.signers), len(agreedBy), ErrQuorumNotMet))
}

func joinIndexes(idx []int) string {
	parts := make([]string, len(idx))
	for i, n := range idx {
		parts[i] = fmt.Sprint(n)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
