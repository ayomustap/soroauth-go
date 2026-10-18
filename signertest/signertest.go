// Package signertest is a conformance suite for soroauth.Signer.
//
// The Signer contract is written in prose in signer.go: Address names the
// credential node a signature belongs to, Sign must honour its context, and a
// failure must not hand back a half-built value. A prose contract is enforced
// by nothing, so an adapter can satisfy the compiler and break it. This
// package turns the rules into checks every implementation can be run through,
// from this module's tests and from the adapter modules' tests.
//
// Typical use, in the implementation's own test file:
//
//	func TestConformance(t *testing.T) {
//	    signertest.Run(t, signertest.Config{
//	        Signer:        mySigner,
//	        Deterministic: true,
//	    })
//	}
//
// The suite checks the contract, not the cryptography: that a signature
// verifies, or has the shape a given account expects, is Config.Verify's job
// because only the caller knows the account.
package signertest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Config says which signer to test and which contract applies to it.
type Config struct {
	// Signer is the implementation under test. A nil Signer is a failure, not
	// a skipped suite: a suite that passes on nothing proves nothing.
	Signer soroauth.Signer

	// Deterministic states that signing the same payload twice returns
	// byte-identical values, as ed25519 does. When true the suite asserts it,
	// and also asserts that two different payloads give different values, which
	// catches a signer that ignores its input. When false (ECDSA, or an
	// interactive device that adds randomness or asks a person) neither is
	// asserted. The suite is told which contract applies rather than guessing.
	Deterministic bool

	// SigningOperations, if set, returns how many times the underlying key
	// has been used to sign. The suite uses it to assert that a cancelled
	// context was honoured *without signing*, not merely that an error came
	// back after the work was done. Leave nil when the implementation cannot
	// report it.
	SigningOperations func() int

	// Verify, if set, is called with each successful signature and its payload
	// and returns an error if the value is not valid for the account. The
	// suite itself only requires a non-empty value.
	Verify func(signature xdr.ScVal, payload [32]byte) error
}

// Violation is one broken rule.
type Violation struct {
	Check  string
	Detail string
}

// String renders the violation as "check: detail".
func (v Violation) String() string { return v.Check + ": " + v.Detail }

// Run runs every check as a subtest of t and fails the ones that are
// violated. It stops the test at once if the signer is nil.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.Signer == nil || isNil(cfg.Signer) {
		t.Fatal("signertest: the signer under test is nil; refusing to pass vacuously")
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			for _, v := range c.run(context.Background(), cfg) {
				t.Errorf("%s", v)
			}
		})
	}
}

// Check runs every check and returns the violations. It is Run without a
// *testing.T, for testing the suite itself. A nil signer is one violation.
func Check(ctx context.Context, cfg Config) []Violation {
	if cfg.Signer == nil || isNil(cfg.Signer) {
		return []Violation{{Check: "signer", Detail: "the signer under test is nil"}}
	}
	var out []Violation
	for _, c := range checks {
		out = append(out, c.run(ctx, cfg)...)
	}
	return out
}

type check struct {
	name string
	run  func(ctx context.Context, cfg Config) []Violation
}

var checks = []check{
	{"address_is_stable", checkAddressStable},
	{"sign_returns_a_signature", checkSignReturns},
	{"preimage_is_not_mutated", checkPreimageUntouched},
	{"cancelled_context_is_honoured", checkCancelled},
	{"expired_context_is_honoured", checkDeadline},
	{"failure_returns_no_partial_value", checkNoPartial},
	{"usable_after_a_refusal", checkUsableAfterFailure},
	{"deterministic_contract", checkDeterminism},
}

func isNil(s soroauth.Signer) bool {
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// fixture builds a well-formed preimage and its payload. The network is not a
// real one, so a signer that reaches a real key signs something no host would
// accept.
func fixture(label string) (xdr.HashIdPreimage, [32]byte, error) {
	var contract xdr.ContractId
	contract[0] = 1
	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId:                 network.ID("signertest conformance - this is not a network"),
			Nonce:                     xdr.Int64(len(label) + 1),
			SignatureExpirationLedger: 1000,
			Invocation: xdr.SorobanAuthorizedInvocation{
				Function: xdr.SorobanAuthorizedFunction{
					Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: &xdr.InvokeContractArgs{
						ContractAddress: xdr.ScAddress{
							Type:       xdr.ScAddressTypeScAddressTypeContract,
							ContractId: &contract,
						},
						FunctionName: xdr.ScSymbol("conformance_" + label),
					},
				},
			},
		},
	}
	payload, err := soroauth.Payload(preimage)
	return preimage, payload, err
}

func violation(check, format string, args ...any) []Violation {
	return []Violation{{Check: check, Detail: fmt.Sprintf(format, args...)}}
}

func isZero(v xdr.ScVal) bool { return reflect.DeepEqual(v, xdr.ScVal{}) }

func checkAddressStable(_ context.Context, cfg Config) []Violation {
	const name = "address_is_stable"
	first := cfg.Signer.Address()
	if first == "" {
		return violation(name, "Address() is empty; a signature with no address belongs to no credential node")
	}
	if _, err := soroauth.ParseAddress(first); err != nil {
		return violation(name, "Address() %q is not a G… or C… address: %v", first, err)
	}
	for i := 0; i < 5; i++ {
		if got := cfg.Signer.Address(); got != first {
			return violation(name, "Address() returned %q, then %q on call %d", first, got, i+2)
		}
	}
	preimage, payload, err := fixture("address")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	_, _ = cfg.Signer.Sign(context.Background(), preimage, payload)
	if got := cfg.Signer.Address(); got != first {
		return violation(name, "Address() changed from %q to %q after Sign", first, got)
	}
	return nil
}

func checkSignReturns(ctx context.Context, cfg Config) []Violation {
	const name = "sign_returns_a_signature"
	preimage, payload, err := fixture("sign")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	val, err := cfg.Signer.Sign(ctx, preimage, payload)
	if err != nil {
		return violation(name, "Sign failed on a well-formed request with a live context: %v", err)
	}
	if isZero(val) {
		return violation(name, "Sign returned a zero ScVal and no error")
	}
	if _, err := val.MarshalBinary(); err != nil {
		return violation(name, "Sign returned a value that does not encode: %v", err)
	}
	if val.Type == xdr.ScValTypeScvVoid {
		return violation(name, "Sign returned Void, which AuthorizeEntry would treat as unsigned")
	}
	if cfg.Verify != nil {
		if err := cfg.Verify(val, payload); err != nil {
			return violation(name, "the signature failed the caller's verification: %v", err)
		}
	}
	return nil
}

func checkPreimageUntouched(ctx context.Context, cfg Config) []Violation {
	const name = "preimage_is_not_mutated"
	preimage, payload, err := fixture("mutate")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	before, err := preimage.MarshalBinary()
	if err != nil {
		return violation(name, "encoding the fixture: %v", err)
	}
	_, _ = cfg.Signer.Sign(ctx, preimage, payload)
	after, err := preimage.MarshalBinary()
	if err != nil {
		return violation(name, "the preimage no longer encodes after Sign: %v", err)
	}
	if !bytes.Equal(before, after) {
		return violation(name, "Sign changed the caller's preimage; signers receive pointers into the entry being authorized")
	}
	return nil
}

func checkCancelled(_ context.Context, cfg Config) []Violation {
	const name = "cancelled_context_is_honoured"
	preimage, payload, err := fixture("cancelled")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var before int
	if cfg.SigningOperations != nil {
		before = cfg.SigningOperations()
	}
	val, err := cfg.Signer.Sign(ctx, preimage, payload)
	var out []Violation
	if err == nil {
		out = append(out, Violation{name, "Sign succeeded with an already-cancelled context; it must return ctx.Err() promptly"})
	} else if !errors.Is(err, context.Canceled) {
		out = append(out, Violation{name, fmt.Sprintf("Sign failed with %v, which does not wrap context.Canceled", err)})
	}
	if cfg.SigningOperations != nil {
		if after := cfg.SigningOperations(); after != before {
			out = append(out, Violation{name, fmt.Sprintf("the key signed %d time(s) under a cancelled context", after-before)})
		}
	}
	_ = val
	return out
}

func checkDeadline(_ context.Context, cfg Config) []Violation {
	const name = "expired_context_is_honoured"
	preimage, payload, err := fixture("deadline")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err = cfg.Signer.Sign(ctx, preimage, payload)
	if err == nil {
		return violation(name, "Sign succeeded with an expired deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return violation(name, "Sign failed with %v, which does not wrap context.DeadlineExceeded", err)
	}
	return nil
}

func checkNoPartial(_ context.Context, cfg Config) []Violation {
	const name = "failure_returns_no_partial_value"
	preimage, payload, err := fixture("partial")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	val, err := cfg.Signer.Sign(ctx, preimage, payload)
	if err != nil && !isZero(val) {
		return violation(name, "Sign returned an error together with a non-zero ScVal (%s); a caller writing the value would write a half-built signature", val.Type)
	}
	return nil
}

func checkUsableAfterFailure(ctx context.Context, cfg Config) []Violation {
	const name = "usable_after_a_refusal"
	preimage, payload, err := fixture("after")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = cfg.Signer.Sign(cancelled, preimage, payload)
	if _, err := cfg.Signer.Sign(ctx, preimage, payload); err != nil {
		return violation(name, "Sign failed on a live context after an earlier cancelled call: %v", err)
	}
	return nil
}

func checkDeterminism(ctx context.Context, cfg Config) []Violation {
	const name = "deterministic_contract"
	if !cfg.Deterministic {
		return nil
	}
	preimage, payload, err := fixture("det")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	a, errA := cfg.Signer.Sign(ctx, preimage, payload)
	b, errB := cfg.Signer.Sign(ctx, preimage, payload)
	if errA != nil || errB != nil {
		return violation(name, "Sign failed: %v, %v", errA, errB)
	}
	ab, _ := a.MarshalBinary()
	bb, _ := b.MarshalBinary()
	if !bytes.Equal(ab, bb) {
		return violation(name, "declared deterministic, but two signatures over the same payload differ")
	}

	otherPreimage, otherPayload, err := fixture("deterministic-other")
	if err != nil {
		return violation(name, "building a fixture: %v", err)
	}
	c, err := cfg.Signer.Sign(ctx, otherPreimage, otherPayload)
	if err != nil {
		return violation(name, "Sign failed: %v", err)
	}
	cb, _ := c.MarshalBinary()
	if bytes.Equal(ab, cb) {
		return violation(name, "two different payloads produced the same signature; the signer is ignoring its input")
	}
	return nil
}
