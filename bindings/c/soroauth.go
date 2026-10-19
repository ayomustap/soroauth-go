//go:build ignore

// The C ABI over the soroauth signing core.
//
// This is the surface the language bindings build on. It is intentionally
// small and string-based: every function takes UTF-8 C strings, returns a
// heap-allocated UTF-8 JSON envelope, and the caller releases it with
// SoroauthFree. JSON rather than a packed struct keeps the ABI stable as the
// library grows — a new field is an added key, not a new calling convention —
// and it is what the Node binding (bindings/node) consumes.
//
// The envelope is either
//
//	{"ok":true,  ...result fields}
//	{"ok":false, "error":"<message>", "kind":"<SENTINEL>"}
//
// `kind` is the Go sentinel the failure wraps, so a binding can raise a typed
// exception rather than string-matching. `kind` is "ERROR" when the failure was
// not one of the exported sentinels (a malformed XDR blob, say).
//
// It is excluded from the normal build with the ignore tag: c-shared needs a C
// toolchain for its target, which the cross-compile matrix does not have. Build
// it explicitly with bindings/c/build.sh, or through the binding that uses it.
//
// The cgo preamble includes stdlib.h because C.free is not declared
// implicitly: cgo generates calloc for C.CString, but SoroauthFree calls free
// directly, and without the include the file does not compile.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// version is the only source of the string SoroauthVersion reports. It is also
// reported by the JSON envelope's callers so a binding can assert the ABI it
// loaded is the one it expects.
const version = "soroauth-c-0.1.0"

// result is the JSON envelope every entry point returns.
type result struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	Kind         string `json:"kind,omitempty"`
	PreimageXDR  string `json:"preimageXdr,omitempty"`
	PayloadHex   string `json:"payloadHex,omitempty"`
	EntryB64     string `json:"entryB64,omitempty"`
	InfoJSON     string `json:"infoJson,omitempty"`
	FindingsJSON string `json:"findingsJson,omitempty"`
	Tree         string `json:"tree,omitempty"`
}

// kindOf maps a Go error to the stable string a binding switches on. Order
// matters only where errors wrap more than one sentinel, which none do.
func kindOf(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, soroauth.ErrSourceAccountCredentials):
		return "SOURCE_ACCOUNT_CREDENTIALS"
	case errors.Is(err, soroauth.ErrUnsupportedCredentials):
		return "UNSUPPORTED_CREDENTIALS"
	case errors.Is(err, soroauth.ErrNoMatchingCredentialNode):
		return "NO_MATCHING_CREDENTIAL_NODE"
	case errors.Is(err, soroauth.ErrDuplicateDelegate):
		return "DUPLICATE_DELEGATE"
	case errors.Is(err, soroauth.ErrSignatureMismatch):
		return "SIGNATURE_MISMATCH"
	case errors.Is(err, soroauth.ErrMissingSigner):
		return "MISSING_SIGNER"
	case errors.Is(err, soroauth.ErrAlreadySigned):
		return "ALREADY_SIGNED"
	case errors.Is(err, soroauth.ErrInvalidExpiration):
		return "INVALID_EXPIRATION"
	case errors.Is(err, soroauth.ErrTooManySignatures):
		return "TOO_MANY_SIGNATURES"
	case errors.Is(err, soroauth.ErrDecodeLimit):
		return "DECODE_LIMIT"
	default:
		return "ERROR"
	}
}

// encode marshals an envelope to a C string. The caller owns it.
func encode(r result) *C.char {
	payload, err := json.Marshal(r)
	if err != nil {
		// Encoding a struct of strings cannot fail; if it somehow does, say so
		// rather than returning nil, which a binding would read as a crash.
		payload = []byte(`{"ok":false,"error":"soroauth: c abi: encoding the result envelope failed","kind":"ERROR"}`)
	}
	return C.CString(string(payload))
}

func okResult(apply func(*result)) *C.char {
	r := result{OK: true}
	apply(&r)
	return encode(r)
}

func failResult(err error) *C.char {
	return encode(result{OK: false, Error: err.Error(), Kind: kindOf(err)})
}

// goString converts a C string that may be NULL into a Go string.
func goString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// decodeEntry parses a base64 XDR SorobanAuthorizationEntry from the ABI.
//
// It decodes through the library's bounded decoder, so an entry the ABI caller
// supplies is refused when it is too deep or too large instead of being decoded
// with the SDK's defaults.
func decodeEntry(b64 string) (xdr.SorobanAuthorizationEntry, error) {
	entry, err := soroauth.DecodeAuthorizationEntry(b64)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: c abi: decoding entry: %w", err)
	}
	return entry, nil
}

func encodeEntry(entry xdr.SorobanAuthorizationEntry) (string, error) {
	raw, err := entry.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("soroauth: c abi: encoding entry: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func options(forAddress string) []soroauth.AuthorizeOption {
	if forAddress == "" {
		return nil
	}
	return []soroauth.AuthorizeOption{soroauth.ForAddress(forAddress)}
}

// SoroauthVersion returns the ABI version string. It is allocated the same way
// every other string is; free it with SoroauthFree.
//
//export SoroauthVersion
func SoroauthVersion() *C.char {
	return C.CString(version)
}

// SoroauthFree releases a string returned by any function in this ABI. Passing
// NULL is a no-op.
//
//export SoroauthFree
func SoroauthFree(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

// SoroauthPreimage builds the HashIdPreimage and its 32-byte payload for an
// address-credential entry.
//
//export SoroauthPreimage
func SoroauthPreimage(entryB64 *C.char, validUntilLedger C.longlong, networkPassphrase *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	if err := requirePassphrase(goString(networkPassphrase)); err != nil {
		return failResult(err)
	}
	preimage, err := soroauth.Preimage(entry, uint32(int64(validUntilLedger)), goString(networkPassphrase))
	if err != nil {
		return failResult(err)
	}
	raw, err := preimage.MarshalBinary()
	if err != nil {
		return failResult(fmt.Errorf("soroauth: c abi: marshalling preimage: %w", err))
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) {
		r.PreimageXDR = base64.StdEncoding.EncodeToString(raw)
		r.PayloadHex = hex.EncodeToString(payload[:])
	})
}

// SoroauthPayload hashes an already-built preimage to its 32-byte payload.
//
// The preimage is caller-supplied base64 XDR, so it is untrusted input, but
// soroauth publishes no bounded decoder for HashIdPreimage — its bounds cover
// authorization entries and transaction envelopes — so this ABI decodes it
// with the SDK's default decoder. A bounded preimage decoder belongs in the
// library, not here.
//
// decode-allow: the base64 blob is a HashIdPreimage the caller supplies, and
// soroauth publishes no bounded decoder for that type; its bounds cover
// authorization entries and transaction envelopes.
//
//export SoroauthPayload
func SoroauthPayload(preimageB64 *C.char) *C.char {
	var preimage xdr.HashIdPreimage
	if err := xdr.SafeUnmarshalBase64(goString(preimageB64), &preimage); err != nil {
		return failResult(fmt.Errorf("soroauth: c abi: decoding preimage: %w", err))
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) { r.PayloadHex = hex.EncodeToString(payload[:]) })
}

// SoroauthWriteSignature writes an externally produced signature ScVal (base64
// XDR) onto every credential node whose address matches.
//
// The signature is caller-supplied base64 XDR, so it is untrusted input, but
// soroauth publishes no bounded decoder for ScVal — its bounds cover
// authorization entries and transaction envelopes — so this ABI decodes it
// with the SDK's default decoder. A bounded ScVal decoder belongs in the
// library, not here.
//
// decode-allow: the base64 blob is an ScVal signature the caller supplies, and
// soroauth publishes no bounded decoder for that type; its bounds cover
// authorization entries and transaction envelopes.
//
//export SoroauthWriteSignature
func SoroauthWriteSignature(entryB64 *C.char, validUntilLedger C.longlong, networkPassphrase *C.char, forAddress *C.char, signatureScvalB64 *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	var signature xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(goString(signatureScvalB64), &signature); err != nil {
		return failResult(fmt.Errorf("soroauth: c abi: decoding signature scval: %w", err))
	}
	target := goString(forAddress)
	if target == "" {
		target, err = topLevelAddress(entry)
		if err != nil {
			return failResult(err)
		}
	}
	signer := soroauth.SignerFunc(target, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		return signature, nil
	})
	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, signer,
		uint32(int64(validUntilLedger)), goString(networkPassphrase), options(goString(forAddress))...,
	)
	if err != nil {
		return failResult(err)
	}
	encoded, err := encodeEntry(signed)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) { r.EntryB64 = encoded })
}

// decodeSeed parses one 32-byte ed25519 seed given as hex and derives its
// keypair. A wrong length is refused here rather than truncated: a seed that is
// silently padded would sign under a key the caller never named.
func decodeSeed(seedHex string) (*keypair.Full, error) {
	seedBytes, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, fmt.Errorf("soroauth: c abi: decoding seed: %w", err)
	}
	if len(seedBytes) != 32 {
		return nil, fmt.Errorf("soroauth: c abi: seed must be 32 bytes, got %d", len(seedBytes))
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("soroauth: c abi: deriving keypair: %w", err)
	}
	return kp, nil
}

// SoroauthAuthorizeWithSeed signs an entry with a 32-byte ed25519 seed given as
// hex. It is the deterministic path a binding uses to run the golden vectors; a
// production caller with a remote signer uses SoroauthWriteSignature instead.
//
//export SoroauthAuthorizeWithSeed
func SoroauthAuthorizeWithSeed(entryB64 *C.char, validUntilLedger C.longlong, networkPassphrase *C.char, seedHex *C.char, forAddress *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	kp, err := decodeSeed(goString(seedHex))
	if err != nil {
		return failResult(err)
	}
	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, soroauth.NewEd25519Signer(kp),
		uint32(int64(validUntilLedger)), goString(networkPassphrase), options(goString(forAddress))...,
	)
	if err != nil {
		return failResult(err)
	}
	encoded, err := encodeEntry(signed)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) { r.EntryB64 = encoded })
}

// SoroauthAuthorizeWithSeeds signs an entry with one or more 32-byte ed25519
// seeds, given as comma-separated hex. One seed signs as a single-key account;
// two or more build an AccountMultiSigner, which sorts the signatures strictly
// ascending by public key and refuses more than the host's
// MAX_ACCOUNT_SIGNATURES = 20 keys (ErrTooManySignatures).
//
// The multi-key path exists because a classic multisig account is a Go-only
// signer shape: without it a binding could only replay the single-key vectors,
// and the multi-signature vector would be reimplemented in the binding instead
// of proved through it. The account address is the target address — the
// forAddress argument when given, otherwise the entry's own top-level address.
//
//export SoroauthAuthorizeWithSeeds
func SoroauthAuthorizeWithSeeds(entryB64 *C.char, validUntilLedger C.longlong, networkPassphrase *C.char, seedsCSV *C.char, forAddress *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	fields := strings.Split(goString(seedsCSV), ",")
	if len(fields) == 0 {
		return failResult(fmt.Errorf("soroauth: c abi: at least one seed is required"))
	}
	keypairs := make([]*keypair.Full, 0, len(fields))
	for _, field := range fields {
		kp, err := decodeSeed(field)
		if err != nil {
			return failResult(err)
		}
		keypairs = append(keypairs, kp)
	}

	target := goString(forAddress)
	if target == "" {
		target, err = topLevelAddress(entry)
		if err != nil {
			return failResult(err)
		}
	}

	var signer soroauth.Signer
	if len(keypairs) == 1 {
		signer = soroauth.NewEd25519Signer(keypairs[0])
	} else {
		signer, err = soroauth.NewAccountMultiSigner(target, keypairs...)
		if err != nil {
			return failResult(err)
		}
	}

	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, signer,
		uint32(int64(validUntilLedger)), goString(networkPassphrase), options(goString(forAddress))...,
	)
	if err != nil {
		return failResult(err)
	}
	encoded, err := encodeEntry(signed)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) { r.EntryB64 = encoded })
}

// SoroauthInspect reports an entry's structure as JSON (soroauth.EntryInfo).
//
//export SoroauthInspect
func SoroauthInspect(entryB64 *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	info, err := soroauth.Inspect(entry)
	if err != nil {
		return failResult(err)
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		return failResult(fmt.Errorf("soroauth: c abi: encoding entry info: %w", err))
	}
	return okResult(func(r *result) { r.InfoJSON = string(encoded) })
}

// SoroauthAnalyze runs the risk analyzer and returns its findings as JSON.
//
//export SoroauthAnalyze
func SoroauthAnalyze(entryB64 *C.char, currentLedger C.longlong) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	cfg := soroauth.DefaultRiskConfig()
	cfg.CurrentLedger = uint32(int64(currentLedger))
	findings, err := soroauth.Analyze(entry, &cfg)
	if err != nil {
		return failResult(err)
	}
	if findings == nil {
		findings = []soroauth.Finding{}
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		return failResult(fmt.Errorf("soroauth: c abi: encoding findings: %w", err))
	}
	return okResult(func(r *result) { r.FindingsJSON = string(encoded) })
}

// SoroauthRenderInvocations renders the invocation tree as ASCII.
//
//export SoroauthRenderInvocations
func SoroauthRenderInvocations(entryB64 *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	tree, err := soroauth.InvocationTreeASCII(entry.RootInvocation)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) { r.Tree = tree })
}

// SoroauthRenderTree renders the credential/delegate tree as ASCII.
//
//export SoroauthRenderTree
func SoroauthRenderTree(entryB64 *C.char) *C.char {
	entry, err := decodeEntry(goString(entryB64))
	if err != nil {
		return failResult(err)
	}
	info, err := soroauth.Inspect(entry)
	if err != nil {
		return failResult(err)
	}
	return okResult(func(r *result) { r.Tree = soroauth.DelegateTreeASCII(info) })
}

// requirePassphrase refuses an empty network passphrase here, where the ABI
// boundary is, rather than letting a Signer fail later.
func requirePassphrase(passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("soroauth: c abi: network passphrase must not be empty")
	}
	return nil
}

// topLevelAddress returns the credential address of an address-based entry.
func topLevelAddress(entry xdr.SorobanAuthorizationEntry) (string, error) {
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if entry.Credentials.Address == nil {
			return "", fmt.Errorf("soroauth: c abi: entry has no address")
		}
		return soroauth.FormatAddress(entry.Credentials.Address.Address)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		if entry.Credentials.AddressV2 == nil {
			return "", fmt.Errorf("soroauth: c abi: entry has no v2 address")
		}
		return soroauth.FormatAddress(entry.Credentials.AddressV2.Address)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if entry.Credentials.AddressWithDelegates == nil {
			return "", fmt.Errorf("soroauth: c abi: entry has no delegate address")
		}
		return soroauth.FormatAddress(entry.Credentials.AddressWithDelegates.AddressCredentials.Address)
	default:
		return "", fmt.Errorf("soroauth: c abi: unsupported credential type")
	}
}

func main() {}
