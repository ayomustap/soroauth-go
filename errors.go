package soroauth

import "errors"

// The sentinel errors soroauth returns. Every one of them is matched with
// errors.Is, and every function that can produce one wraps it with
// fmt.Errorf("soroauth: <operation>: %w", err) so the message says what was
// being attempted while the sentinel stays comparable.
//
// These describe refusals, not failures. soroauth produces signatures that
// authorize value to move, so wherever the protocol or the caller's intent is
// ambiguous the library declines and returns one of these rather than guessing
// at what was meant.
var (
	// ErrSourceAccountCredentials is returned when a signing payload is
	// requested for an entry that uses SOROBAN_CREDENTIALS_SOURCE_ACCOUNT.
	//
	// That arm has no payload to sign: the transaction envelope's own
	// signature covers it, so there is no HashIdPreimage variant for it and
	// nothing for a Signer to do. It is an error from Preimage, but not from
	// AuthorizeEntry, which passes such entries through untouched so callers
	// can hand it every entry simulation returned.
	ErrSourceAccountCredentials = errors.New("credentials are source-account, which carry no signature payload")

	// ErrUnsupportedCredentials is returned for a credentials arm this
	// library does not know how to sign.
	//
	// The four defined arms are SOURCE_ACCOUNT (0), ADDRESS (1), ADDRESS_V2
	// (2) and ADDRESS_WITH_DELEGATES (3). A value outside that set means the
	// entry was built against a protocol this build does not implement, so
	// signing it would be a guess about a wire format that has not been read.
	ErrUnsupportedCredentials = errors.New("unsupported credentials type")

	// ErrNoMatchingCredentialNode is returned when no credential node in the
	// entry carries the address the signature was meant for.
	//
	// This is the fail-closed half of soroauth's target-address rule: a
	// signature is only ever written onto a node whose address equals the
	// target, so when nothing matches, the call fails instead of writing the
	// signature somewhere it does not belong. It is the error a caller sees
	// after signing with the wrong key, or naming an address via ForAddress
	// that is not in the delegate tree.
	ErrNoMatchingCredentialNode = errors.New("no credential node matches the target address")

	// ErrDuplicateDelegate is returned when one address appears twice within a
	// single delegates array.
	//
	// CAP-71-01 requires each delegates array to be sorted by address in
	// increasing order, which leaves no room for a repeat at the same level.
	// The same address at two different nesting levels is a different thing
	// and is allowed. The wrapped error names the offending address.
	ErrDuplicateDelegate = errors.New("duplicate delegate address at the same level")

	// ErrSignatureMismatch is returned when a signer's own signature fails to
	// verify against the payload it was just given.
	//
	// Ed25519Signer verifies its own output before handing it back. The cost
	// is one verification; what it catches is a corrupted key, a faulty
	// signer, or memory damage producing a signature that would be rejected
	// on-chain only after fees were paid.
	ErrSignatureMismatch = errors.New("signature does not verify against the payload")

	// ErrMissingSigner is returned by AuthorizeAll when an address-arm entry
	// has no signer for its address. The wrapped error names the address.
	//
	// AuthorizeAll never silently skips an entry: an unsigned address entry
	// means a transaction that is accepted, charged for, and then fails during
	// application. Refusing the whole batch is the cheaper failure.
	ErrMissingSigner = errors.New("no signer for address")

	// ErrAlreadySigned is returned when signing would overwrite or invalidate
	// a signature that is already present.
	//
	// Under CAP-71-01 every signature-bearing node in a delegates entry
	// commits to the same payload, and that payload includes the expiration
	// ledger, so re-signing one node with a different expiration silently
	// invalidates the signatures on all the others. It is also returned when
	// an entry that already carries a signature is converted to a different
	// credentials arm, because the payload type changes underneath the
	// existing signature. Pass AllowResign when overwriting is intended.
	ErrAlreadySigned = errors.New("credential node is already signed")

	// ErrInvalidExpiration is returned for an expiration ledger that cannot be
	// used: zero, an overflowing sum, or one that disagrees with the
	// expiration already committed to by existing signatures on the entry.
	//
	// Zero is rejected rather than treated as "no expiry" because the host
	// rejects an entry once the current ledger is past the stored value
	// (rs-soroban-env soroban-env-host/src/auth.rs, verify_and_consume_nonce:
	// `if ledger_seq > *live_until_ledger` → "signature has expired"), so a
	// zero expiration is not permissive, it is already expired.
	ErrInvalidExpiration = errors.New("invalid signature expiration ledger")

	// ErrTooManySignatures is returned when more signing keys are given for a
	// classic account than the host will accept.
	//
	// The host caps a classic account signature vector at MAX_ACCOUNT_SIGNATURES,
	// which is 20 (rs-soroban-env
	// soroban-env-host/src/builtin_contracts/account_contract.rs:25, enforced
	// at :185 with "too many account signers"). Exceeding it is rejected here
	// rather than on-chain.
	ErrTooManySignatures = errors.New("too many signatures for a classic account")

	// ErrDecodeLimit is returned when untrusted input is refused for exceeding
	// one of the bounds this library applies to it: MaxDecodeInputBytes on the
	// encoded size, or MaxDecodeDepth on XDR nesting and on the recursive walks
	// over an already-decoded entry.
	//
	// The Go SDK's defaults are not a bound chosen for untrusted input:
	// xdr.SafeUnmarshalBase64 sets MaxInputLen from the input it was handed, so
	// it can never refuse an input for being too long, and it leaves go-xdr's
	// default depth of 1500 in place. An entry that comes from a simulation,
	// the network, or a caller is untrusted, so DecodeAuthorizationEntry and
	// the traversals apply explicit limits and report this sentinel when one
	// bites. A refusal is the fail-closed outcome: the alternative is doing
	// unbounded work on input an attacker chose.
	ErrDecodeLimit = errors.New("untrusted input exceeds a decode limit")

	// ErrNoInvokeOperation is returned when a transaction envelope carries no
	// invokeHostFunction operation, and therefore no authorization entries at
	// all.
	//
	// An empty result would be indistinguishable from an envelope whose invoke
	// operation simply has nothing to authorize, so this is an error rather
	// than a nil slice: a caller that asked for an envelope's entries and got
	// none silently would go on to submit a transaction it never authorized.
	ErrNoInvokeOperation = errors.New("envelope carries no invokeHostFunction operation")

	// ErrUnsupportedEnvelope is returned for a transaction envelope whose type
	// this library does not know how to read.
	//
	// The three defined arms are ENVELOPE_TYPE_TX_V0 (0), ENVELOPE_TYPE_TX (2)
	// and ENVELOPE_TYPE_TX_FEE_BUMP (5). A value outside that set means the
	// envelope was built against a protocol this build does not implement, so
	// reading it would be a guess about a wire format that has not been read.
	ErrUnsupportedEnvelope = errors.New("unsupported transaction envelope type")

	// ErrUnsignedCredentialNode is returned by AuthorizeAll, when
	// RequireAllSigned was given, when a credential node in a signed entry's
	// tree carries no signature.
	//
	// AuthorizeAll cannot know an account's own policy — a 2-of-3 delegate
	// tree, or an account that authenticates purely through delegates and
	// leaves its own top-level node Void, are both legitimate under
	// CAP-71-01 — so by default it stops at "at least one signer matched
	// somewhere". RequireAllSigned is the opt-in for a caller who does know
	// their policy requires every node signed, such as an account whose
	// custom __check_auth calls delegate_account_auth for every stored
	// delegate. The wrapped error names the first unsigned node found, in
	// entry order and then tree order.
	ErrUnsignedCredentialNode = errors.New("credential node was left unsigned")

	// ErrDelegatePlanUnmatched is returned by AuthorizeAll when a delegate
	// plan passed to WithDelegatePlans names an address that matches no
	// entry's top-level address in the batch.
	//
	// A plan entry that matches nothing is very likely a typo or a stale
	// plan left over from a removed entry, and applying it silently would
	// mean the caller's intended delegate wrapping never happened — the same
	// fail-closed reasoning AuthorizeAll already applies to a missing
	// signer.
	ErrDelegatePlanUnmatched = errors.New("delegate plan address matches no entry in the batch")

	// ErrNonceAlreadyReserved is returned by a NonceTracker's Reserve when
	// the given nonce was already reserved for the given address.
	//
	// This is a local, best-effort check, not the protocol's own guard: the
	// host is the sole authority on whether a nonce is valid, and it is
	// verify_and_consume_nonce (rs-soroban-env soroban-env-host/src/auth.rs)
	// that actually rejects a repeat, on-chain, after the transaction has
	// been submitted and its fee charged. A NonceTracker exists to catch the
	// collision earlier — before a signature is even built — for nonces this
	// tracker's own store has seen; it has no visibility into a nonce
	// consumed elsewhere.
	ErrNonceAlreadyReserved = errors.New("nonce already reserved for this address")

	// ErrWebAuthnMalformedJSON is returned by ParseWebAuthnAssertion when the
	// assertion is not valid JSON, or when its clientDataJSON is not valid
	// JSON.
	//
	// These are separate layers of the same input (WebAuthn Level 2 §5.1.4
	// serializes the credential, §5.8.1 defines the client data), so a
	// truncation or a stray byte in either is refused here rather than
	// producing a partially filled assertion.
	ErrWebAuthnMalformedJSON = errors.New("webauthn assertion is not valid JSON")

	// ErrWebAuthnMissingField is returned by ParseWebAuthnAssertion when a
	// field the assertion must carry is absent or empty: one of
	// response.clientDataJSON, response.authenticatorData or
	// response.signature, or the challenge inside clientDataJSON.
	//
	// A missing field is never defaulted. An assertion without a challenge
	// cannot bind the browser ceremony to the payload, and an assertion
	// without a signature would authorize nothing.
	ErrWebAuthnMissingField = errors.New("webauthn assertion is missing a field")

	// ErrWebAuthnMalformedField is returned by ParseWebAuthnAssertion when a
	// field is present but unusable: the base64url transport encoding of
	// clientDataJSON, authenticatorData, signature or the challenge is
	// invalid, or the credential type is not "public-key".
	//
	// It is distinct from ErrWebAuthnMissingField so a caller can tell a
	// truncated capture (a field that never arrived) from a corrupted one
	// (a field that arrived but does not decode).
	ErrWebAuthnMalformedField = errors.New("webauthn assertion field is not valid base64url")

	// ErrWebAuthnTruncatedAuthenticatorData is returned by
	// ParseWebAuthnAssertion when the authenticator data is shorter than its
	// fixed prefix.
	//
	// WebAuthn Level 2 §6.1 fixes that prefix at 32 bytes of RP ID hash, one
	// byte of flags and four bytes of sign counter: 37 bytes before any
	// attested credential data or extensions. Anything shorter cannot carry
	// the flags, so a caller that checked for user presence or verification
	// would be reading past the end of what it was given.
	ErrWebAuthnTruncatedAuthenticatorData = errors.New("webauthn authenticatorData is shorter than its 37-byte fixed prefix")

	// ErrWebAuthnChallengeMismatch is returned when the challenge the
	// authenticator signed does not equal the payload expected of it.
	//
	// This is the security-critical check. WebAuthn binds a ceremony to a
	// relying party through the challenge (WebAuthn Level 2 §5.8.1, §7.1 step
	// 11), and the challenge is what ties the assertion the browser produced
	// to this exact Soroban authorization payload. Accepting an assertion
	// whose challenge is different would be accepting a signature over
	// somebody else's ceremony.
	ErrWebAuthnChallengeMismatch = errors.New("webauthn challenge does not match the expected payload")
	// ErrSignerAddressMismatch is returned when a managed signer's public key
	// does not belong to the account address the signer was configured or
	// constructed with.
	//
	// A managed signer (Vault, a Ledger device) hands back a public key that
	// this library did not choose. If that key does not derive the expected
	// G… address, every signature it produces would be written onto a
	// credential node it cannot authorize, or would fail on-chain after fees
	// were paid. Refusing at construction is the fail-closed outcome.
	ErrSignerAddressMismatch = errors.New("signer public key does not match the configured address")

	// ErrVaultUnauthorized is returned when Vault rejects the token used for a
	// transit operation (HTTP 403).
	//
	// Transit key material never leaves Vault, so the caller's token is the
	// only credential this library holds. It does not renew tokens: renewal
	// belongs in a Vault Agent or an explicit token helper, and an expired
	// token must surface as this error rather than as a retry loop.
	ErrVaultUnauthorized = errors.New("vault rejected the token")

	// ErrVaultKeyNotFound is returned when the configured transit key does not
	// exist (HTTP 404).
	ErrVaultKeyNotFound = errors.New("vault transit key not found")

	// ErrVaultKeyType is returned when the configured transit key is not an
	// ed25519 signing key.
	//
	// Stellar account signatures are ed25519; an aes256-gcm96, ECDSA or RSA
	// transit key cannot produce the shape the host's account contract checks,
	// so the mismatch is refused before any signature is requested.
	ErrVaultKeyType = errors.New("vault transit key is not an ed25519 key")

	// ErrLedgerUnavailable is returned when the Ledger transport cannot reach a
	// device at all: no device, a failed exchange, or a malformed response.
	//
	// It is deliberately distinct from ErrLedgerLocked and ErrLedgerWrongApp,
	// because the three call for different user actions (plug the device in,
	// unlock it, open the Stellar app), and a single "device error" would make
	// the caller guess.
	ErrLedgerUnavailable = errors.New("ledger device is unavailable")

	// ErrLedgerLocked is returned when the connected Ledger device is locked
	// (status word 0x5515).
	ErrLedgerLocked = errors.New("ledger device is locked")

	// ErrLedgerWrongApp is returned when the APDU the Stellar app would handle
	// is rejected as an unsupported class or instruction (status words 0x6E00
	// and 0x6D00), which in practice means the Stellar app is not the app
	// currently open on the device.
	ErrLedgerWrongApp = errors.New("ledger device is not running the Stellar app")

	// ErrLedgerBlindSigningDisabled is returned when the device refuses a
	// signing request because "Blind signing" is not enabled in the Stellar
	// app's settings (status word 0x6C66).
	//
	// The Soroban-authorization signing path renders a decoded review and still
	// gates it behind that setting (LedgerHQ/app-stellar
	// src/app_ui/sign_soroban_auth.rs), so the user must enable it even though
	// nothing is being blind-signed.
	ErrLedgerBlindSigningDisabled = errors.New("blind signing is disabled in the Ledger Stellar app settings")

	// ErrLedgerDenied is returned when the user rejects the review on the device
	// (status word 0x6985).
	ErrLedgerDenied = errors.New("the request was rejected on the ledger device")

	// ErrAttestationMalformed is returned by VerifyAttestation when the
	// attestation object, authenticator data, client data or a certificate in
	// the statement cannot be parsed. It is distinct from ErrAttestationInvalid
	// so a caller can tell a broken client from a forged registration.
	ErrAttestationMalformed = errors.New("webauthn attestation is malformed")

	// ErrAttestationInvalid is returned by VerifyAttestation when the
	// attestation parses but fails a check the WebAuthn specification
	// requires: a signature, the RP ID hash, the challenge, the origin, a
	// flag, or a certificate requirement. The wrapped text names the check and
	// the specification section.
	ErrAttestationInvalid = errors.New("webauthn attestation failed verification")

	// ErrAttestationUnsupportedFormat is returned by VerifyAttestation for a
	// statement format, signature algorithm or credential key type it does not
	// verify. It is refused rather than skipped, because skipping would report
	// an unchecked statement as attested.
	ErrAttestationUnsupportedFormat = errors.New("webauthn attestation format or algorithm is not supported")

	// ErrPolicyRefusal marks a signing failure that is a decision, not a
	// fault: a policy engine, an approval flow or a human said no. A signer
	// chain stops on it and never falls through to another signer, because
	// asking a second signer after the first one refused would route around
	// the refusal. Signers that refuse wrap this sentinel.
	ErrPolicyRefusal = errors.New("signing refused by policy")

	// ErrSignerTransient marks a signing failure that a different signer could
	// reasonably clear, such as a timeout or an unreachable service. A signer
	// chain falls through only on errors that wrap it; every other error is
	// terminal, so an error the chain cannot classify stops it. Use
	// MarkTransient to mark an error.
	ErrSignerTransient = errors.New("transient signer failure")

	// ErrChainExhausted is returned by a fallback chain when every signer was
	// tried and every one failed transiently.
	ErrChainExhausted = errors.New("every signer in the chain failed")

	// ErrQuorumNotMet is returned by a quorum chain when fewer signers
	// returned a signature than the quorum requires.
	ErrQuorumNotMet = errors.New("signer quorum was not met")

	// ErrQuorumDisagreement is returned by a quorum chain when signers
	// returned different signatures. It is a refusal, not a vote: one of them
	// is wrong, and the chain does not guess which.
	ErrQuorumDisagreement = errors.New("signers disagree on the signature")
)

// NoMatchingCredentialNodeError is returned when no credential node in the
// entry carries the address the signature was meant for, and exposes that
// address as a field so callers can recover it with errors.As instead of
// parsing the error string.
//
// It wraps ErrNoMatchingCredentialNode, so errors.Is keeps matching the
// sentinel. The Error text is exactly the sentinel's text; the address is
// formatted into the surrounding message by the call site (for example
// "soroauth: authorize entry: <address>: …") and is available here as Address.
//
// This is the fail-closed half of soroauth's target-address rule under
// CAP-71-01: a signature is only ever written onto a node whose address equals
// the target, so when nothing matches the call fails rather than writing the
// signature somewhere it does not belong.
type NoMatchingCredentialNodeError struct {
	// Address is the target address that matched no credential node.
	Address string
}

// Error implements error. The text is identical to
// ErrNoMatchingCredentialNode.Error so existing message assertions and log
// parsers see no change; Address is carried separately for errors.As.
func (e *NoMatchingCredentialNodeError) Error() string {
	return ErrNoMatchingCredentialNode.Error()
}

// Unwrap returns ErrNoMatchingCredentialNode so errors.Is keeps working.
func (e *NoMatchingCredentialNodeError) Unwrap() error {
	return ErrNoMatchingCredentialNode
}

// DuplicateDelegateError is returned when one address appears twice within a
// single delegates array, and exposes that address as a field so callers can
// recover it with errors.As instead of parsing the error string.
//
// It wraps ErrDuplicateDelegate, so errors.Is keeps matching the sentinel.
// The Error text is exactly the sentinel's text; the address is formatted into
// the surrounding message by the call site and is available here as Address.
//
// CAP-71-01 requires each delegates array to be sorted by address in
// increasing order, which leaves no room for a repeat at the same level. The
// same address at two different nesting levels is allowed and does not
// produce this error.
type DuplicateDelegateError struct {
	// Address is the delegate address that appears more than once at one level.
	Address string
}

// Error implements error. The text is identical to
// ErrDuplicateDelegate.Error so existing message assertions and log parsers
// see no change; Address is carried separately for errors.As.
func (e *DuplicateDelegateError) Error() string {
	return ErrDuplicateDelegate.Error()
}

// Unwrap returns ErrDuplicateDelegate so errors.Is keeps working.
func (e *DuplicateDelegateError) Unwrap() error {
	return ErrDuplicateDelegate
}

// MissingSignerError is returned when an address-arm entry has no signer for
// its address (or a classic multisig account has no keys), and exposes that
// address as a field so callers can recover it with errors.As instead of
// parsing the error string.
//
// It wraps ErrMissingSigner, so errors.Is keeps matching the sentinel. The
// Error text is exactly the sentinel's text; the address is formatted into the
// surrounding message by the call site and is available here as Address.
//
// AuthorizeAll never silently skips an entry: an unsigned address entry means
// a transaction that is accepted, charged for, and then fails during
// application. Refusing the whole batch is the cheaper failure.
type MissingSignerError struct {
	// Address is the entry address (or classic account address) that has no
	// applicable signer. It is empty only where the call site had no address
	// to name, such as a nil Signer.
	Address string
}

// Error implements error. The text is identical to ErrMissingSigner.Error so
// existing message assertions and log parsers see no change; Address is
// carried separately for errors.As.
func (e *MissingSignerError) Error() string {
	return ErrMissingSigner.Error()
}

// Unwrap returns ErrMissingSigner so errors.Is keeps working.
func (e *MissingSignerError) Unwrap() error {
	return ErrMissingSigner
}

// UnsignedCredentialNodeError is returned by AuthorizeAll, when
// RequireAllSigned was given, for the first credential node found with no
// signature, and exposes that address as a field so callers can recover it
// with errors.As instead of parsing the error string.
//
// It wraps ErrUnsignedCredentialNode, so errors.Is keeps matching the
// sentinel. The Error text is exactly the sentinel's text; the address is
// formatted into the surrounding message by the call site and is available
// here as Address.
type UnsignedCredentialNodeError struct {
	// Address is the credential node's address that carries no signature.
	Address string
}

// Error implements error. The text is identical to
// ErrUnsignedCredentialNode.Error so existing message assertions and log
// parsers see no change; Address is carried separately for errors.As.
func (e *UnsignedCredentialNodeError) Error() string {
	return ErrUnsignedCredentialNode.Error()
}

// Unwrap returns ErrUnsignedCredentialNode so errors.Is keeps working.
func (e *UnsignedCredentialNodeError) Unwrap() error {
	return ErrUnsignedCredentialNode
}

// DelegatePlanUnmatchedError is returned by AuthorizeAll when a delegate plan
// names an address that matches no entry in the batch, and exposes that
// address as a field so callers can recover it with errors.As instead of
// parsing the error string.
//
// It wraps ErrDelegatePlanUnmatched, so errors.Is keeps matching the
// sentinel. The Error text is exactly the sentinel's text; the address is
// formatted into the surrounding message by the call site and is available
// here as Address.
type DelegatePlanUnmatchedError struct {
	// Address is the delegate plan's address that matched no entry.
	Address string
}

// Error implements error. The text is identical to
// ErrDelegatePlanUnmatched.Error so existing message assertions and log
// parsers see no change; Address is carried separately for errors.As.
func (e *DelegatePlanUnmatchedError) Error() string {
	return ErrDelegatePlanUnmatched.Error()
}

// Unwrap returns ErrDelegatePlanUnmatched so errors.Is keeps working.
func (e *DelegatePlanUnmatchedError) Unwrap() error {
	return ErrDelegatePlanUnmatched
}

// NonceAlreadyReservedError is returned by a NonceTracker's Reserve when the
// given nonce was already reserved for the given address, and exposes both
// as fields so callers can recover them with errors.As instead of parsing
// the error string.
//
// It wraps ErrNonceAlreadyReserved, so errors.Is keeps matching the
// sentinel. The Error text is exactly the sentinel's text; the address is
// formatted into the surrounding message by the call site and is available
// here as Address, with Nonce alongside it.
type NonceAlreadyReservedError struct {
	// Address is the address the nonce was already reserved for.
	Address string
	// Nonce is the value that collided.
	Nonce int64
}

// Error implements error. The text is identical to
// ErrNonceAlreadyReserved.Error so existing message assertions and log
// parsers see no change; Address and Nonce are carried separately for
// errors.As.
func (e *NonceAlreadyReservedError) Error() string {
	return ErrNonceAlreadyReserved.Error()
}

// Unwrap returns ErrNonceAlreadyReserved so errors.Is keeps working.
func (e *NonceAlreadyReservedError) Unwrap() error {
	return ErrNonceAlreadyReserved
}
