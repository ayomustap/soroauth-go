package soroauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// isNilSigner reports a nil interface or an interface holding a nil pointer,
// either of which would panic on first use.
func isNilSigner(s Signer) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// possessionNetworkPassphrase is the network passphrase the possession check
// signs under. It names no network, so the network ID derived from it
// (SHA-256 of the passphrase, CAP-46-11) is the ID of no network: a signature
// over a payload that commits to it is invalid on testnet, on the public
// network and on any private one.
const possessionNetworkPassphrase = "soroauth possession check - this is not a network"

// possessionFunction is the function name in the throwaway invocation.
const possessionFunction = "soroauth_possession_check"

// PossessionReport is the outcome of CheckPossession.
type PossessionReport struct {
	// Address is the address the signer claims.
	Address string `json:"address"`
	// Verdict is VerdictVerified when the signer's signature verifies and its
	// key is the claimed address's own key, VerdictInvalid when it does not,
	// and VerdictCannotCheck when the library cannot decide offline, the same
	// distinction VerifyEntry draws.
	Verdict VerifyVerdict `json:"verdict"`
	// Reason says why in plain language whenever Verdict is not
	// VerdictVerified.
	Reason string `json:"reason,omitempty"`
}

// Passed reports whether the check proved key control. cannot_check is not a
// pass.
func (r PossessionReport) Passed() bool { return r.Verdict == VerdictVerified }

// PossessionOption configures CheckPossession.
type PossessionOption func(*possessionConfig)

type possessionConfig struct {
	foreignKeys bool
}

// AllowAccountSigningKeys states that the account may be signed for by keys
// other than its own, as a classic multisig account is. Signatures that verify
// but are made by other keys are then reported VerdictCannotCheck instead of
// VerdictInvalid: whether those keys are registered signers of the account is
// on-chain state.
func AllowAccountSigningKeys() PossessionOption {
	return func(c *possessionConfig) { c.foreignKeys = true }
}

// CheckPossession signs a payload that cannot be a real authorization and
// verifies the result against the address the signer claims, so a signer that
// does not control its address is found at startup rather than by a
// transaction that fails on-chain after fees are paid. A KMS key alias that
// points at the wrong key, or an account address that is not the key's, passes
// every other startup check.
//
// Why the payload cannot be replayed as an authorization. It is the payload of
// a genuine authorization preimage (CAP-46-11, ENVELOPE_TYPE_SOROBAN_AUTHORIZATION),
// so signers that inspect the preimage or insist the payload is its hash work
// unchanged, but the preimage commits to a network ID derived from a
// passphrase that names no network, to the function soroauth_possession_check
// on the zero contract, and to a random nonce. A host derives the payload from
// the real network ID, so a signature over this one verifies for no entry on
// any network. The nonce is random on every call so a recorded response is not
// proof of present control.
//
// For a classic (G…) address the built-in signature shape is verified
// offline. An address-bound claim must match: the signing key has to be the
// address's own key, otherwise the report is VerdictInvalid. For a contract
// (C…) address, or a signature in a shape the library does not define, the
// report is VerdictCannotCheck, never a pass.
//
// The limit of a pass: it proves the signer holds the key for the address. It
// does not prove that key is a signer of the account on-chain, or meets its
// thresholds; only a submission shows that.
//
// A returned error means the signer could not be exercised (nil signer,
// cancelled context, a signing failure); a signer that signed wrongly is a
// VerdictInvalid report, not an error.
func CheckPossession(ctx context.Context, signer Signer, opts ...PossessionOption) (PossessionReport, error) {
	var cfg possessionConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if isNilSigner(signer) {
		return PossessionReport{}, fmt.Errorf("soroauth: check possession: %w", ErrMissingSigner)
	}
	address := signer.Address()
	report := PossessionReport{Address: address}

	scAddress, err := ParseAddress(address)
	if err != nil {
		return PossessionReport{}, fmt.Errorf("soroauth: check possession: %w", err)
	}

	preimage, payload, err := possessionPreimage()
	if err != nil {
		return PossessionReport{}, fmt.Errorf("soroauth: check possession: %w", err)
	}

	signature, err := signer.Sign(ctx, preimage, payload)
	if err != nil {
		return PossessionReport{}, fmt.Errorf("soroauth: check possession: %s: %w", address, err)
	}

	if scAddress.Type != xdr.ScAddressTypeScAddressTypeAccount {
		report.Verdict = VerdictCannotCheck
		report.Reason = contractAccountNote
		return report, nil
	}
	return verifyAccountPossession(report, signature, payload, address, cfg), nil
}

// possessionPreimage builds the throwaway preimage and its payload.
func possessionPreimage() (xdr.HashIdPreimage, [32]byte, error) {
	var nonceBytes [8]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return xdr.HashIdPreimage{}, [32]byte{}, fmt.Errorf("reading a nonce: %w", err)
	}
	nonce := int64(binary.BigEndian.Uint64(nonceBytes[:]))

	var zeroContract xdr.ContractId
	function := xdr.ScSymbol(possessionFunction)
	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId:                 network.ID(possessionNetworkPassphrase),
			Nonce:                     xdr.Int64(nonce),
			SignatureExpirationLedger: 0,
			Invocation: xdr.SorobanAuthorizedInvocation{
				Function: xdr.SorobanAuthorizedFunction{
					Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: &xdr.InvokeContractArgs{
						ContractAddress: xdr.ScAddress{
							Type:       xdr.ScAddressTypeScAddressTypeContract,
							ContractId: &zeroContract,
						},
						FunctionName: function,
					},
				},
			},
		},
	}
	payload, err := Payload(preimage)
	if err != nil {
		return xdr.HashIdPreimage{}, [32]byte{}, err
	}
	return preimage, payload, nil
}

// verifyAccountPossession checks a classic account's signature value. The
// built-in shape is a vector of {public_key, signature} maps; every one must
// verify, and the account's own key must be among them unless the caller said
// other keys may sign for it.
func verifyAccountPossession(report PossessionReport, signature xdr.ScVal, payload [32]byte, address string, cfg possessionConfig) PossessionReport {
	rawKey, err := rawEd25519Key(address)
	if err != nil {
		report.Verdict = VerdictInvalid
		report.Reason = err.Error()
		return report
	}

	if !isSigned(signature) {
		report.Verdict = VerdictInvalid
		report.Reason = "the signer returned no signature (Void or an empty vector)"
		return report
	}
	if signature.Type != xdr.ScValTypeScvVec || signature.Vec == nil || *signature.Vec == nil || len(**signature.Vec) == 0 {
		report.Verdict = VerdictCannotCheck
		report.Reason = shapeNote
		return report
	}

	ownKey := false
	for i, element := range **signature.Vec {
		publicKey, rawSignature, err := parseAccountSignature(scVec(element))
		if err != nil {
			report.Verdict = VerdictCannotCheck
			report.Reason = fmt.Sprintf("%s (%v)", shapeNote, err)
			return report
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), payload[:], rawSignature) {
			report.Verdict = VerdictInvalid
			report.Reason = fmt.Sprintf("signature %d does not verify over the payload: the signer does not control the key it presents", i)
			return report
		}
		if string(publicKey) == string(rawKey) {
			ownKey = true
		}
	}

	switch {
	case ownKey:
		report.Verdict = VerdictVerified
	case cfg.foreignKeys:
		report.Verdict = VerdictCannotCheck
		report.Reason = "the signatures verify, but are made by keys other than the account's own; whether those keys are signers of the account is on-chain state"
	default:
		report.Verdict = VerdictInvalid
		report.Reason = "the signatures verify, but not under the key of " + address + ": the signer's key does not match its configured address (pass AllowAccountSigningKeys for an account signed by other keys)"
	}
	return report
}
