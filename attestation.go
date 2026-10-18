package soroauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Passkey enrolment is the half of the WebAuthn flow that decides whether a
// public key is trusted at all; webauthn.go parses the other half, the
// assertions made at signing time. Without checking the attestation a wallet
// enrols whatever key a client claims. Every check below cites the section of
// W3C WebAuthn Level 2 (https://www.w3.org/TR/webauthn-2/) it implements.

// AttestationFormat is the attestation statement format (WebAuthn §8).
type AttestationFormat string

const (
	// AttestationFormatNone is the "none" format (§8.7): the authenticator
	// makes no statement about itself.
	AttestationFormatNone AttestationFormat = "none"
	// AttestationFormatPacked is the "packed" format (§8.2).
	AttestationFormatPacked AttestationFormat = "packed"
)

// AttestationTrust says how much the attestation statement proves. The levels
// are ordered, and only AttestationTrustRooted says anything about the
// authenticator itself.
type AttestationTrust string

const (
	// AttestationTrustNone is the "none" format. Nothing about the
	// authenticator is proven, and it is not a weak pass: the client could
	// have made the key anywhere. The AAGUID is whatever the client sent.
	AttestationTrustNone AttestationTrust = "none"
	// AttestationTrustSelf is packed self attestation (§8.2.2): the key signed
	// over its own registration. That proves the registrant holds the private
	// key and nothing else.
	AttestationTrustSelf AttestationTrust = "self"
	// AttestationTrustUnrooted is packed attestation with an x5c chain
	// (§8.2.1) whose signature verifies under the leaf certificate, but no
	// trust roots were supplied. The certificate is self-consistent; whether
	// it belongs to a real authenticator model is not established.
	AttestationTrustUnrooted AttestationTrust = "unrooted"
	// AttestationTrustRooted is packed attestation with an x5c chain that
	// verifies to a root the caller supplied. This is the only level at which
	// the AAGUID and the hardware claim are authenticated, and they are
	// exactly as trustworthy as the roots passed in.
	AttestationTrustRooted AttestationTrust = "rooted"
)

// AttestationRequest is an attestation to verify and what it must match.
type AttestationRequest struct {
	// AttestationObject is the CBOR attestationObject from the authenticator's
	// response (§6.5.4).
	AttestationObject []byte
	// ClientDataJSON is the exact clientDataJSON bytes the browser produced.
	// The authenticator signs a hash of these bytes, so they must not be
	// re-serialised.
	ClientDataJSON []byte
	// RPID is the relying party identifier the credential must be scoped to.
	RPID string
	// Origin is the exact origin the ceremony must have run on.
	Origin string
	// Challenge is the raw challenge the server issued for this ceremony.
	Challenge []byte
	// RequireUserVerification refuses a credential created without a PIN or
	// biometric (UV flag, §7.1 step 15).
	RequireUserVerification bool
	// TrustRoots anchors an x5c chain. Without it a certificate chain can
	// reach at most AttestationTrustUnrooted. With it, a chain that does not
	// verify is refused rather than downgraded.
	TrustRoots *x509.CertPool
	// Now is the time certificate validity is checked at; zero means now.
	Now time.Time
}

// AttestationResult is what a verified attestation established.
//
// The fields split into what was proven and what the client merely asserted.
// Proven and Asserted say the same thing in words, for logs and operator
// output; the typed fields are for code.
type AttestationResult struct {
	Format AttestationFormat
	Trust  AttestationTrust

	// AAGUID is the authenticator model identifier. It is only authenticated
	// when AAGUIDAuthenticated is true; otherwise it is a claim.
	AAGUID              [16]byte
	AAGUIDAuthenticated bool

	// HardwareBacked is true only at AttestationTrustRooted. This library
	// carries no list of which roots belong to hardware authenticators (that
	// is FIDO Metadata Service territory), so the claim is exactly as strong
	// as the roots the caller chose to pass. It is never inferred from the
	// format, the AAGUID, or any flag the client controls.
	HardwareBacked bool

	CredentialID []byte
	// PublicKey is the credential's P-256 key.
	PublicKey *ecdsa.PublicKey
	// PublicKeySEC1 is PublicKey as the 65-byte uncompressed point, the form
	// NewPasskeySignerFromAssertion and the wallet contracts take.
	PublicKeySEC1 []byte

	SignCount      uint32
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackedUp       bool

	// Proven lists what the verification established. Asserted lists what the
	// result carries that no check covered.
	Proven   []string
	Asserted []string
}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80

	coseAlgES256 = -7
	coseKtyEC2   = 2
	coseCrvP256  = 1

	// maxCredentialIDLength is the largest credential ID WebAuthn allows
	// (§5.8.3).
	maxCredentialIDLength = 1023
)

// oidFIDOGenCEAAGUID is id-fido-gen-ce-aaguid, the certificate extension that
// carries the AAGUID (§8.2.1).
var oidFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

func attestationInvalid(format string, args ...any) error {
	return fmt.Errorf("soroauth: verify attestation: %w: %s", ErrAttestationInvalid, fmt.Sprintf(format, args...))
}

func attestationMalformed(format string, args ...any) error {
	return fmt.Errorf("soroauth: verify attestation: %w: %s", ErrAttestationMalformed, fmt.Sprintf(format, args...))
}

// VerifyAttestation verifies a passkey registration (WebAuthn §7.1) and says
// what it proved.
//
// It checks the client data (steps 7 to 11), parses the attestation object and
// its authenticator data (steps 12 and 13), checks the RP ID hash, user
// presence and user verification (steps 15 to 17), and verifies the statement
// for the "none" and "packed" formats. Any other format is refused with
// ErrAttestationUnsupportedFormat: skipping an unverified statement would
// report a key as attested when nothing was checked. Only ES256 credential
// keys are accepted, because secp256r1 is the only passkey key type a Soroban
// host verifies.
//
// A pass proves the registration is internally consistent and, at
// AttestationTrustRooted, which attestation key signed it. It does not prove
// the credential will be accepted by any contract, and it does not prove the
// key is hardware backed beyond what the supplied roots mean. See
// AttestationResult.
func VerifyAttestation(req AttestationRequest) (AttestationResult, error) {
	if req.RPID == "" || req.Origin == "" || len(req.Challenge) == 0 {
		return AttestationResult{}, attestationInvalid("RPID, Origin and Challenge are all required: " +
			"verifying without them would not bind the attestation to this ceremony")
	}

	if err := checkRegistrationClientData(req); err != nil {
		return AttestationResult{}, err
	}
	clientDataHash := sha256.Sum256(req.ClientDataJSON)

	format, stmt, authData, err := parseAttestationObject(req.AttestationObject)
	if err != nil {
		return AttestationResult{}, err
	}

	result, err := parseRegistrationAuthData(authData, req)
	if err != nil {
		return AttestationResult{}, err
	}
	result.Format = AttestationFormat(format)

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)

	switch AttestationFormat(format) {
	case AttestationFormatNone:
		if len(stmt) != 0 {
			return AttestationResult{}, attestationInvalid("none attestation statement must be empty (§8.7), has %d entries", len(stmt))
		}
		result.Trust = AttestationTrustNone
	case AttestationFormatPacked:
		if err := verifyPackedStatement(&result, stmt, signed, req); err != nil {
			return AttestationResult{}, err
		}
	default:
		return AttestationResult{}, fmt.Errorf("soroauth: verify attestation: %w: format %q", ErrAttestationUnsupportedFormat, format)
	}

	result.finish()
	return result, nil
}

// finish fills the derived fields and the proven/asserted summaries.
func (r *AttestationResult) finish() {
	r.AAGUIDAuthenticated = r.Trust == AttestationTrustRooted
	r.HardwareBacked = r.Trust == AttestationTrustRooted

	r.Proven = append(r.Proven,
		"the client data is a webauthn.create for the expected origin and challenge",
		"the authenticator data is scoped to the expected RP ID",
		"the credential public key is a valid P-256 point",
	)
	if r.UserPresent {
		r.Proven = append(r.Proven, "user presence was reported by the authenticator data covered by this registration")
	}

	switch r.Trust {
	case AttestationTrustNone:
		r.Asserted = append(r.Asserted,
			"nothing about the authenticator: the none format is no statement at all",
			"the AAGUID "+formatAAGUID(r.AAGUID)+" and every flag are claims by whoever made the request")
	case AttestationTrustSelf:
		r.Proven = append(r.Proven, "the registrant held the private key for the credential public key (self attestation)")
		r.Asserted = append(r.Asserted,
			"the authenticator model: self attestation is signed by the credential key itself",
			"the AAGUID "+formatAAGUID(r.AAGUID))
	case AttestationTrustUnrooted:
		r.Proven = append(r.Proven, "the attestation signature verifies under the leaf certificate in x5c and the certificate meets §8.2.1")
		r.Asserted = append(r.Asserted,
			"that the certificate belongs to a real authenticator: no trust roots were supplied",
			"the AAGUID "+formatAAGUID(r.AAGUID)+" (signed by an unanchored key)")
	case AttestationTrustRooted:
		r.Proven = append(r.Proven,
			"the x5c chain verifies to a supplied trust root",
			"the AAGUID "+formatAAGUID(r.AAGUID)+" is covered by an attestation signature from that chain")
		r.Asserted = append(r.Asserted,
			"that the supplied roots belong to hardware authenticators: this library does not know which do")
	}
	if r.BackupEligible || r.BackedUp {
		r.Asserted = append(r.Asserted, "backup flags (BE/BS): a synced passkey is not a device-bound key")
	}
}

// formatAAGUID renders an AAGUID in the 8-4-4-4-12 form used in the FIDO
// metadata.
func formatAAGUID(a [16]byte) string {
	h := hex.EncodeToString(a[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// checkRegistrationClientData implements §7.1 steps 7 to 11 for a creation
// ceremony.
func checkRegistrationClientData(req AttestationRequest) error {
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(req.ClientDataJSON, &cd); err != nil {
		return attestationMalformed("clientDataJSON is not valid JSON: %v", err)
	}
	// Step 8.
	if cd.Type != "webauthn.create" {
		return attestationInvalid("clientDataJSON type is %q, want \"webauthn.create\" (§7.1 step 8)", cd.Type)
	}
	// Step 9.
	challenge, err := decodeBase64Loose(cd.Challenge)
	if err != nil {
		return attestationMalformed("clientDataJSON challenge is not base64url: %v", err)
	}
	if subtle.ConstantTimeCompare(challenge, req.Challenge) != 1 {
		return attestationInvalid("clientDataJSON challenge does not match the one issued (§7.1 step 9)")
	}
	// Step 10.
	if cd.Origin != req.Origin {
		return attestationInvalid("clientDataJSON origin is %q, want %q (§7.1 step 10)", cd.Origin, req.Origin)
	}
	return nil
}

// parseAttestationObject reads the three members of the attestation object
// (§6.5.4): fmt, attStmt and authData. Any other member is refused.
func parseAttestationObject(raw []byte) (format string, stmt cborMap, authData []byte, err error) {
	value, rest, err := decodeCBOR(raw)
	if err != nil {
		return "", nil, nil, attestationMalformed("attestationObject: %v", err)
	}
	if len(rest) != 0 {
		return "", nil, nil, attestationMalformed("attestationObject has %d trailing bytes", len(rest))
	}
	obj, ok := value.(cborMap)
	if !ok {
		return "", nil, nil, attestationMalformed("attestationObject is %T, not a map", value)
	}
	if len(obj) != 3 {
		return "", nil, nil, attestationMalformed("attestationObject has %d members, want exactly fmt, attStmt and authData", len(obj))
	}

	fmtValue, _ := obj.get("fmt")
	format, ok = fmtValue.(string)
	if !ok {
		return "", nil, nil, attestationMalformed("attestationObject fmt is missing or not text")
	}
	stmtValue, _ := obj.get("attStmt")
	stmt, ok = stmtValue.(cborMap)
	if !ok {
		return "", nil, nil, attestationMalformed("attestationObject attStmt is missing or not a map")
	}
	authValue, _ := obj.get("authData")
	authData, ok = authValue.([]byte)
	if !ok {
		return "", nil, nil, attestationMalformed("attestationObject authData is missing or not bytes")
	}
	return format, stmt, authData, nil
}

// parseRegistrationAuthData reads authenticator data (§6.1) from a
// registration: the fixed 37-byte prefix, then the attested credential data
// (§6.5.1) that the AT flag announces.
func parseRegistrationAuthData(authData []byte, req AttestationRequest) (AttestationResult, error) {
	var result AttestationResult
	if len(authData) < 37 {
		return result, attestationMalformed("authData is %d bytes, shorter than the 37-byte prefix", len(authData))
	}

	// Step 13: the RP ID hash.
	wantRPIDHash := sha256.Sum256([]byte(req.RPID))
	if !bytes.Equal(authData[:32], wantRPIDHash[:]) {
		return result, attestationInvalid("authData rpIdHash does not match the SHA-256 of RP ID %q (§7.1 step 13)", req.RPID)
	}

	flags := authData[32]
	// Step 14.
	if flags&flagUP == 0 {
		return result, attestationInvalid("user presence flag is not set (§7.1 step 14)")
	}
	// Step 15.
	if req.RequireUserVerification && flags&flagUV == 0 {
		return result, attestationInvalid("user verification flag is not set and verification was required (§7.1 step 15)")
	}
	// Attested credential data must be present in a registration (§6.1).
	if flags&flagAT == 0 {
		return result, attestationInvalid("attested credential data flag (AT) is not set on a registration (§6.1)")
	}

	result.UserPresent = true
	result.UserVerified = flags&flagUV != 0
	result.BackupEligible = flags&flagBE != 0
	result.BackedUp = flags&flagBS != 0
	result.SignCount = binary.BigEndian.Uint32(authData[33:37])

	rest := authData[37:]
	if len(rest) < 18 {
		return result, attestationMalformed("attested credential data is %d bytes, shorter than 18", len(rest))
	}
	copy(result.AAGUID[:], rest[:16])
	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if idLen == 0 || idLen > maxCredentialIDLength {
		return result, attestationMalformed("credential ID length %d is outside 1..%d (§5.8.3)", idLen, maxCredentialIDLength)
	}
	if len(rest) < idLen {
		return result, attestationMalformed("credential ID claims %d bytes with %d remaining", idLen, len(rest))
	}
	result.CredentialID = append([]byte(nil), rest[:idLen]...)
	rest = rest[idLen:]

	keyValue, rest, err := decodeCBOR(rest)
	if err != nil {
		return result, attestationMalformed("credential public key: %v", err)
	}
	if err := parseCOSEKeyES256(keyValue, &result); err != nil {
		return result, err
	}

	// Anything after the key must be the extension map the ED flag announces.
	if flags&flagED != 0 {
		ext, rest2, err := decodeCBOR(rest)
		if err != nil {
			return result, attestationMalformed("authenticator extensions: %v", err)
		}
		if _, ok := ext.(cborMap); !ok {
			return result, attestationMalformed("authenticator extensions are %T, not a map", ext)
		}
		rest = rest2
	}
	if len(rest) != 0 {
		return result, attestationMalformed("authData has %d unexplained trailing bytes", len(rest))
	}
	return result, nil
}

// parseCOSEKeyES256 reads a COSE_Key (RFC 9052 §7) and accepts only an EC2
// P-256 ES256 key (RFC 9053 §2.1 and §7.1). The point is checked to lie on the
// curve; a key that does not is a malformed registration, not a weak one.
func parseCOSEKeyES256(value any, result *AttestationResult) error {
	m, ok := value.(cborMap)
	if !ok {
		return attestationMalformed("credential public key is %T, not a COSE_Key map", value)
	}
	kty, _ := m.get(int64(1))
	alg, _ := m.get(int64(3))
	crv, _ := m.get(int64(-1))
	if kty != int64(coseKtyEC2) || alg != int64(coseAlgES256) || crv != int64(coseCrvP256) {
		return fmt.Errorf("soroauth: verify attestation: %w: credential key is not EC2/ES256/P-256 (kty=%v alg=%v crv=%v); "+
			"only secp256r1 passkeys can be verified by a Soroban host",
			ErrAttestationUnsupportedFormat, kty, alg, crv)
	}
	xv, _ := m.get(int64(-2))
	yv, _ := m.get(int64(-3))
	x, okx := xv.([]byte)
	y, oky := yv.([]byte)
	if !okx || !oky || len(x) != 32 || len(y) != 32 {
		return attestationMalformed("COSE key coordinates must be two 32-byte strings")
	}

	sec1 := make([]byte, 0, 65)
	sec1 = append(sec1, 0x04)
	sec1 = append(sec1, x...)
	sec1 = append(sec1, y...)
	// ecdh validates that the point is on the curve.
	if _, err := ecdh.P256().NewPublicKey(sec1); err != nil {
		return attestationMalformed("credential public key is not a point on P-256: %v", err)
	}
	result.PublicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	result.PublicKeySEC1 = sec1
	return nil
}

// verifyPackedStatement implements §8.2 verification procedure for the packed
// format.
func verifyPackedStatement(result *AttestationResult, stmt cborMap, signed []byte, req AttestationRequest) error {
	for _, p := range stmt {
		switch p.key {
		case "alg", "sig", "x5c":
		case "ecdaaKeyId":
			return fmt.Errorf("soroauth: verify attestation: %w: packed ECDAA attestation was removed from WebAuthn Level 2",
				ErrAttestationUnsupportedFormat)
		default:
			return attestationMalformed("packed attStmt has unexpected member %v", p.key)
		}
	}

	algValue, _ := stmt.get("alg")
	alg, ok := algValue.(int64)
	if !ok {
		return attestationMalformed("packed attStmt alg is missing or not an integer")
	}
	sigValue, _ := stmt.get("sig")
	sig, ok := sigValue.([]byte)
	if !ok || len(sig) == 0 {
		return attestationMalformed("packed attStmt sig is missing or not bytes")
	}
	// Only ES256 is verified. Another algorithm is refused, not skipped.
	if alg != coseAlgES256 {
		return fmt.Errorf("soroauth: verify attestation: %w: packed algorithm %d (only ES256, -7, is verified)",
			ErrAttestationUnsupportedFormat, alg)
	}

	digest := sha256.Sum256(signed)

	x5cValue, hasX5C := stmt.get("x5c")
	if !hasX5C {
		// §8.2.2 self attestation: signed by the credential key itself.
		if !ecdsa.VerifyASN1(result.PublicKey, digest[:], sig) {
			return attestationInvalid("self attestation signature does not verify under the credential public key (§8.2.2)")
		}
		result.Trust = AttestationTrustSelf
		return nil
	}

	// §8.2.1 attestation with a certificate.
	list, ok := x5cValue.([]any)
	if !ok || len(list) == 0 {
		return attestationMalformed("packed attStmt x5c must be a non-empty array")
	}
	certs := make([]*x509.Certificate, 0, len(list))
	for i, item := range list {
		der, ok := item.([]byte)
		if !ok {
			return attestationMalformed("x5c[%d] is not bytes", i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return attestationMalformed("x5c[%d] is not a certificate: %v", i, err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]

	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafKey.Curve != elliptic.P256() {
		return fmt.Errorf("soroauth: verify attestation: %w: attestation certificate key is not ECDSA P-256, which the ES256 algorithm requires",
			ErrAttestationUnsupportedFormat)
	}
	if !ecdsa.VerifyASN1(leafKey, digest[:], sig) {
		return attestationInvalid("attestation signature does not verify under the x5c leaf certificate (§8.2.1)")
	}
	if err := checkPackedCertificate(leaf, result.AAGUID); err != nil {
		return err
	}

	result.Trust = AttestationTrustUnrooted
	if req.TrustRoots != nil {
		now := req.Now
		if now.IsZero() {
			now = time.Now()
		}
		intermediates := x509.NewCertPool()
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         req.TrustRoots,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return attestationInvalid("x5c chain does not verify to a supplied trust root: %v", err)
		}
		result.Trust = AttestationTrustRooted
	}
	return nil
}

// checkPackedCertificate enforces the packed attestation certificate
// requirements (§8.2.1, "Packed attestation statement certificate
// requirements").
func checkPackedCertificate(cert *x509.Certificate, aaguid [16]byte) error {
	if cert.Version != 3 {
		return attestationInvalid("attestation certificate version is %d, must be 3 (§8.2.1)", cert.Version)
	}
	subject := cert.Subject
	if len(subject.Country) == 0 || len(subject.Organization) == 0 || subject.CommonName == "" {
		return attestationInvalid("attestation certificate subject must carry C, O and CN (§8.2.1)")
	}
	if len(subject.OrganizationalUnit) != 1 || subject.OrganizationalUnit[0] != "Authenticator Attestation" {
		return attestationInvalid("attestation certificate subject OU must be exactly \"Authenticator Attestation\" (§8.2.1)")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return attestationInvalid("attestation certificate must carry Basic Constraints with CA=false (§8.2.1)")
	}
	return checkAAGUIDExtension(cert.Extensions, aaguid)
}

// checkAAGUIDExtension enforces that id-fido-gen-ce-aaguid, when present,
// is not critical and matches the AAGUID in the authenticator data (§8.2.1).
func checkAAGUIDExtension(extensions []pkix.Extension, aaguid [16]byte) error {
	for _, ext := range extensions {
		if !ext.Id.Equal(oidFIDOGenCEAAGUID) {
			continue
		}
		if ext.Critical {
			return attestationInvalid("id-fido-gen-ce-aaguid extension must not be critical (§8.2.1)")
		}
		var value []byte
		rest, err := asn1.Unmarshal(ext.Value, &value)
		if err != nil || len(rest) != 0 {
			return attestationMalformed("id-fido-gen-ce-aaguid extension is not a DER OCTET STRING")
		}
		if !bytes.Equal(value, aaguid[:]) {
			return attestationInvalid("certificate AAGUID %x does not match authenticator data AAGUID %x (§8.2.1)", value, aaguid)
		}
	}
	return nil
}
