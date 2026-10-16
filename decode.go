package soroauth

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// The deliberate limits applied to every untrusted authorization entry this
// library decodes.
//
// The values are chosen to be far above anything a legitimate Soroban
// authorization entry reaches while still being small enough that a
// pathological one is refused instead of consuming the process:
//
//   - Depth 64. The go-stellar-sdk default is 1500
//     (go-xdr/xdr3 DecodeDefaultMaxDepth), which bounds recursion but leaves a
//     long way to go before refusing. Real entries nest an invocation tree,
//     some ScVal containers, and — for CAP-71-01 — a delegate tree; the golden
//     vectors in testdata/vectors/ are nowhere near 64 levels. 64 is generous
//     for all three credential arms and still far below the SDK default.
//   - Input 1 MiB decoded. Soroban authorization entries carry a small
//     invocation tree and its arguments; 1 MiB is orders of magnitude more than
//     the golden vectors need and keeps a multi-megabyte base64 blob from being
//     decoded at all. go-xdr's MaxInputLen, which the SDK sets to the decoded
//     length of the input, then bounds allocation during the decode itself: a
//     doctored array length cannot read past the bytes the input actually
//     carries.
const (
	// MaxDecodeDepth is the maximum nesting depth accepted when decoding an
	// untrusted authorization entry, and the maximum nesting depth Inspect and
	// the traversal helpers will walk.
	MaxDecodeDepth = 64

	// MaxDecodeInputBytes is the maximum decoded size of an untrusted
	// authorization entry.
	MaxDecodeInputBytes = 1 << 20
)

// DecodeAuthorizationEntry decodes a base64 XDR SorobanAuthorizationEntry that
// came from somewhere else.
//
// This is the entry point to use for anything Inspect or the CLI consumes:
// an entry produced by a simulation, fetched from the network, or pasted by a
// caller is untrusted input, and the Go SDK's defaults are not a bound chosen
// for that case. xdr.SafeUnmarshalBase64 applies go-xdr's default maximum depth
// of 1500 and, because it sets MaxInputLen from the input it was handed, it can
// never refuse an input for being too long. DecodeAuthorizationEntry applies
// the explicit limits documented on MaxDecodeDepth and MaxDecodeInputBytes
// instead, and reports a limit refusal as ErrDecodeLimit.
//
// The limits are fixed, not parameters. A caller that needs a different bound
// has a protocol reason to make, and that reason belongs in this library rather
// than in every call site.
//
// This function does not change the bytes of a valid entry: it decodes the same
// value xdr.SafeUnmarshalBase64 would, and re-encoding it reproduces the input.
func DecodeAuthorizationEntry(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	if encoded == "" {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: decode authorization entry: input is empty")
	}

	// SafeUnmarshalBase64WithOptions overwrites MaxInputLen with the decoded
	// length of whatever it is given, so the input length has to be checked
	// here, before any base64 or XDR work happens.
	if len(encoded) > base64.StdEncoding.EncodedLen(MaxDecodeInputBytes) {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: decode authorization entry: %d base64 bytes exceeds the %d-byte decoded limit: %w",
			len(encoded), MaxDecodeInputBytes, ErrDecodeLimit)
	}

	var entry xdr.SorobanAuthorizationEntry
	err := xdr.SafeUnmarshalBase64WithOptions(encoded, &entry, xdr.DecodeOptions{
		MaxDepth: MaxDecodeDepth,
	})
	if err != nil {
		// go-xdr returns ErrMaxDecodingDepthReached (through the SDK's
		// re-export) when the depth limit bites, so the refusal is
		// distinguishable from malformed input.
		if errors.Is(err, xdr.ErrMaxDecodingDepthReached) {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
				"soroauth: decode authorization entry: nesting exceeds the %d-level limit: %w",
				MaxDecodeDepth, ErrDecodeLimit)
		}
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: decode authorization entry: %w", err)
	}

	return entry, nil
}

// DecodeTransactionEnvelope decodes a base64 XDR TransactionEnvelope that
// came from somewhere else.
//
// It is DecodeAuthorizationEntry's counterpart for the other shape the CLI and
// the verification surfaces accept, and it exists for the same reason: an
// envelope handed to this library — from a simulation, from a wallet, from a
// command line — is untrusted input, and xdr.SafeUnmarshalBase64 applies
// go-xdr's default limits (a maximum depth of 1500, and a MaxInputLen taken
// from the input itself, so it can never refuse an input for being too long)
// rather than a bound chosen for this case. It applies the limits documented on
// MaxDecodeDepth and MaxDecodeInputBytes, and reports a refusal as
// ErrDecodeLimit.
//
// The limits are the same ones the entry decoder uses, because they bound the
// same thing: how much of a process an untrusted blob may consume. The input
// bound is on the decoded size, and a Soroban transaction carrying an
// authorization entry is far below it.
//
// This function does not change the bytes of a valid envelope: it decodes the
// same value xdr.SafeUnmarshalBase64 would, and re-encoding it reproduces the
// input.
func DecodeTransactionEnvelope(encoded string) (xdr.TransactionEnvelope, error) {
	if encoded == "" {
		return xdr.TransactionEnvelope{}, fmt.Errorf(
			"soroauth: decode transaction envelope: input is empty")
	}

	if len(encoded) > base64.StdEncoding.EncodedLen(MaxDecodeInputBytes) {
		return xdr.TransactionEnvelope{}, fmt.Errorf(
			"soroauth: decode transaction envelope: %d base64 bytes exceeds the %d-byte decoded limit: %w",
			len(encoded), MaxDecodeInputBytes, ErrDecodeLimit)
	}

	var envelope xdr.TransactionEnvelope
	err := xdr.SafeUnmarshalBase64WithOptions(encoded, &envelope, xdr.DecodeOptions{
		MaxDepth: MaxDecodeDepth,
	})
	if err != nil {
		if errors.Is(err, xdr.ErrMaxDecodingDepthReached) {
			return xdr.TransactionEnvelope{}, fmt.Errorf(
				"soroauth: decode transaction envelope: nesting exceeds the %d-level limit: %w",
				MaxDecodeDepth, ErrDecodeLimit)
		}
		return xdr.TransactionEnvelope{}, fmt.Errorf(
			"soroauth: decode transaction envelope: %w", err)
	}

	return envelope, nil
}

// checkTraversalDepth guards the recursive walks over an already-decoded entry.
//
// A decoded entry is bounded by whatever decoder produced it. A caller that
// used the SDK directly may have allowed the SDK default of 1500 levels, and a
// caller that built the struct in memory can nest as deeply as it likes, so
// Inspect and the delegate helpers enforce the same MaxDecodeDepth bound on
// their own recursion rather than trusting the entry's provenance.
//
// The error is not prefixed here: every caller wraps it with the operation it
// was performing, which is where the useful context lives.
func checkTraversalDepth(depth int) error {
	if depth > MaxDecodeDepth {
		return fmt.Errorf(
			"nesting exceeds the %d-level limit: %w", MaxDecodeDepth, ErrDecodeLimit)
	}
	return nil
}
