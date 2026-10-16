package soroauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// nestedInvocation builds an invocation tree depth levels deep. The leaf is a
// contract call; every level above it hangs off the previous one.
func nestedInvocation(t *testing.T, depth int) xdr.SorobanAuthorizedInvocation {
	t.Helper()

	leaf := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: mustParse(t, testContractAddress(t, "soroauth-decode-leaf")),
				FunctionName:    xdr.ScSymbol("transfer"),
			},
		},
	}

	for i := 0; i < depth; i++ {
		leaf = xdr.SorobanAuthorizedInvocation{
			Function:       leaf.Function,
			SubInvocations: []xdr.SorobanAuthorizedInvocation{leaf},
		}
	}
	return leaf
}

// superDeepEntry encodes a source-account entry whose invocation tree nests
// well past the deliberate decode limit.
func superDeepEntry(t *testing.T, depth int) string {
	t.Helper()

	entry := xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount},
		RootInvocation: nestedInvocation(t, depth),
	}
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		t.Fatalf("marshalling the pathological entry: %v", err)
	}
	return encoded
}

// TestDecodeAuthorizationEntryRejectsPathologicalDepth is the regression the
// issue is about: a deeply nested entry must be refused, promptly, instead of
// being fully decoded. The SDK default is 1500 levels, so an entry well past
// our limit would otherwise decode happily.
func TestDecodeAuthorizationEntryRejectsPathologicalDepth(t *testing.T) {
	encoded := superDeepEntry(t, MaxDecodeDepth*4)

	got, err := DecodeAuthorizationEntry(encoded)
	if err == nil {
		t.Fatalf("decoding a %d-level entry succeeded, returning %+v", MaxDecodeDepth*4, got)
	}
	if !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("error %q does not match ErrDecodeLimit", err)
	}
	if got.Credentials.Type != 0 || got.RootInvocation.Function.ContractFn != nil {
		t.Errorf("DecodeAuthorizationEntry returned a value alongside an error: %+v", got)
	}
}

// TestDecodeAuthorizationEntryRejectsOversizedInput proves the length check
// runs before any base64 or XDR work: the input is not valid base64 at all, yet
// it is refused as a limit rather than a malformed-input error.
func TestDecodeAuthorizationEntryRejectsOversizedInput(t *testing.T) {
	oversized := strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxDecodeInputBytes)+4)

	got, err := DecodeAuthorizationEntry(oversized)
	if err == nil {
		t.Fatalf("decoding a %d-byte input succeeded, returning %+v", len(oversized), got)
	}
	if !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("error %q does not match ErrDecodeLimit", err)
	}
}

// TestDecodeAuthorizationEntryRejectsEmptyInput keeps the empty case an error
// rather than a silently zero-valued entry.
func TestDecodeAuthorizationEntryRejectsEmptyInput(t *testing.T) {
	got, err := DecodeAuthorizationEntry("")
	if err == nil {
		t.Fatalf("decoding an empty input succeeded, returning %+v", got)
	}
	if got.Credentials.Type != 0 || got.RootInvocation.Function.ContractFn != nil {
		t.Errorf("DecodeAuthorizationEntry returned a value alongside an error: %+v", got)
	}
}

// TestDecodeAuthorizationEntryReadsEveryGoldenVector proves the bound is above
// every committed entry and that the decoder changes nothing: re-encoding the
// decoded entry reproduces the recorded bytes.
func TestDecodeAuthorizationEntryReadsEveryGoldenVector(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			want, err := base64.StdEncoding.DecodeString(v.UnsignedEntryXDR)
			if err != nil {
				t.Fatalf("decoding the recorded entry: %v", err)
			}

			entry, err := DecodeAuthorizationEntry(v.UnsignedEntryXDR)
			if err != nil {
				t.Fatalf("DecodeAuthorizationEntry returned an unexpected error: %v", err)
			}

			got, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("re-marshalling the decoded entry: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("re-encoded entry differs from the record\n want %x\n  got %x", want, got)
			}
		})
	}
}

// deeplyNestedDelegateTree builds a delegates array depth levels deep. Every
// level repeats the same address, which CAP-71-01 allows across levels.
func deeplyNestedDelegateTree(t *testing.T, depth int) []xdr.SorobanDelegateSignature {
	t.Helper()

	address := mustParse(t, testKeypair(t, "soroauth-decode-delegate").Address())
	node := xdr.SorobanDelegateSignature{
		Address:   address,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}
	for i := 0; i < depth; i++ {
		node = xdr.SorobanDelegateSignature{
			Address:         address,
			Signature:       xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			NestedDelegates: []xdr.SorobanDelegateSignature{node},
		}
	}
	return []xdr.SorobanDelegateSignature{node}
}

// TestInspectRefusesAPathologicalDelegateTree covers the other untrusted-input
// boundary: an entry that was decoded elsewhere may have allowed a deeper tree
// than DecodeAuthorizationEntry does, so Inspect bounds its own walk.
func TestInspectRefusesAPathologicalDelegateTree(t *testing.T) {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   mustParse(t, testKeypair(t, "soroauth-decode-top").Address()),
					Nonce:                     1,
					SignatureExpirationLedger: 42,
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: deeplyNestedDelegateTree(t, MaxDecodeDepth*2),
			},
		},
		RootInvocation: nestedInvocation(t, 0),
	}

	got, err := Inspect(entry)
	if err == nil {
		t.Fatalf("Inspecting a %d-level delegate tree succeeded, returning %+v", MaxDecodeDepth*2, got)
	}
	if !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("error %q does not match ErrDecodeLimit", err)
	}

	if err := ValidateDelegateOrder(entry); !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("ValidateDelegateOrder error %q does not match ErrDecodeLimit", err)
	}
}

// TestInspectRefusesPathologicalSubInvocations is the invocation-tree half of
// the same guard.
func TestInspectRefusesPathologicalSubInvocations(t *testing.T) {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount},
		RootInvocation: nestedInvocation(t, MaxDecodeDepth*2),
	}

	if _, err := Inspect(entry); !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("Inspect error %q does not match ErrDecodeLimit", err)
	}
}

// TestWithDelegatesRefusesAPathologicalTree proves the delegate builder refuses
// a caller-supplied tree past the same ceiling rather than recursing into it.
func TestWithDelegatesRefusesAPathologicalTree(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	tree := Delegate{Address: testKeypair(t, "soroauth-decode-delegate").Address()}
	for i := 0; i < MaxDecodeDepth*2; i++ {
		tree = Delegate{
			Address: testKeypair(t, "soroauth-decode-delegate").Address(),
			Nested:  []Delegate{tree},
		}
	}

	got, err := WithDelegates(base, testValidUntilLedger, []Delegate{tree}, nil)
	if err == nil {
		t.Fatalf("WithDelegates accepted a %d-level tree, returning %+v", MaxDecodeDepth*2, got)
	}
	if !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("error %q does not match ErrDecodeLimit", err)
	}
}

// FuzzDecodeAuthorizationEntry feeds arbitrary bytes through the bounded
// decoder. Anything must either decode or fail with a clean error, never a
// panic, and whatever the decoder consumed must re-encode identically without
// growing: the XDR decoder reads a prefix of its input and ignores trailing
// bytes, so a byte-identical round-trip holds only for the consumed prefix.
// An input past the size bound must refuse with ErrDecodeLimit rather than
// decoding at all.
func FuzzDecodeAuthorizationEntry(f *testing.F) {
	// f is passed to the helper directly, which takes testing.TB. A
	// &testing.T{} literal would be an uninitialised struct: Helper() and
	// Fatalf() on one panic rather than reporting, so a seed that failed to
	// build would take the target down instead of failing it.
	seed := entryForArm(f, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	if raw, err := seed.MarshalBinary(); err == nil {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := base64.StdEncoding.EncodeToString(data)
		entry, err := DecodeAuthorizationEntry(encoded)
		if err != nil {
			if len(data) > MaxDecodeInputBytes && !errors.Is(err, ErrDecodeLimit) {
				t.Errorf("oversized input (%d bytes) refused without ErrDecodeLimit: %v", len(data), err)
			}
			return
		}
		roundTrip, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("DecodeAuthorizationEntry returned an entry that does not re-encode: %v", err)
		}
		if len(roundTrip) > len(data) {
			t.Errorf("re-encoding grew %d input bytes into %d", len(data), len(roundTrip))
		} else if !bytes.Equal(roundTrip, data[:len(roundTrip)]) {
			t.Errorf("re-encoding changed the %d consumed bytes of %d input bytes", len(roundTrip), len(data))
		}
	})
}

// TestDecodeTransactionEnvelopeReadsAValidEnvelope proves the bound is above a
// real Soroban transaction and that the decoder changes nothing: re-encoding
// the decoded envelope reproduces the input bytes.
func TestDecodeTransactionEnvelopeReadsAValidEnvelope(t *testing.T) {
	envelope, err := xdr.MarshalBase64(transactionEnvelope(t,
		invokeOperation(t, entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 7))))
	if err != nil {
		t.Fatalf("encoding the test envelope: %v", err)
	}
	want, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		t.Fatalf("decoding the test envelope: %v", err)
	}

	got, err := DecodeTransactionEnvelope(envelope)
	if err != nil {
		t.Fatalf("DecodeTransactionEnvelope returned an unexpected error: %v", err)
	}
	roundTrip, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshalling the decoded envelope: %v", err)
	}
	if !bytes.Equal(roundTrip, want) {
		t.Errorf("re-encoded envelope differs from the input\n want %x\n  got %x", want, roundTrip)
	}
}

// TestDecodeTransactionEnvelopeRejectsEmptyInput keeps the empty case an error
// rather than a silently zero-valued envelope.
func TestDecodeTransactionEnvelopeRejectsEmptyInput(t *testing.T) {
	if _, err := DecodeTransactionEnvelope(""); err == nil {
		t.Fatal("decoding an empty input succeeded")
	}
}

// TestDecodeTransactionEnvelopeRejectsOversizedInput proves the length check
// runs before any base64 or XDR work: the input is not valid base64 at all,
// yet it is refused as a limit rather than as malformed input.
func TestDecodeTransactionEnvelopeRejectsOversizedInput(t *testing.T) {
	oversized := strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxDecodeInputBytes)+4)

	_, err := DecodeTransactionEnvelope(oversized)
	if err == nil {
		t.Fatalf("decoding a %d-byte input succeeded", len(oversized))
	}
	if !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("error %q does not match ErrDecodeLimit", err)
	}
}

// TestDecodeTransactionEnvelopeRejectsPathologicalDepth is the envelope half of
// the depth guard: an envelope whose operation carries a deeply nested
// invocation tree must be refused rather than fully decoded, even though the
// SDK's default of 1500 levels would accept it.
func TestDecodeTransactionEnvelopeRejectsPathologicalDepth(t *testing.T) {
	deep := xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount},
		RootInvocation: nestedInvocation(t, MaxDecodeDepth*4),
	}
	envelope, err := xdr.MarshalBase64(transactionEnvelope(t, invokeOperation(t, deep)))
	if err != nil {
		t.Fatalf("encoding the pathological envelope: %v", err)
	}

	got, err := DecodeTransactionEnvelope(envelope)
	if err == nil {
		t.Fatalf("decoding a %d-level envelope succeeded, returning %+v", MaxDecodeDepth*4, got)
	}
	if !errors.Is(err, ErrDecodeLimit) {
		t.Errorf("error %q does not match ErrDecodeLimit", err)
	}
}
