package soroauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The vectors in testdata/attestation/vectors.json are registrations made by
// real authenticators (hardware keys and platform authenticators), copied from
// the test data of github.com/go-webauthn/webauthn; testdata/attestation/README.md
// records where each came from. They are never edited. The tamper tests below
// do not rewrite a vector either: they flip bytes in a copy, at offsets found
// by parsing it, so a failing check is caused by exactly that field.

type attestationVector struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Source            string `json:"source"`
	RPID              string `json:"rp_id"`
	Origin            string `json:"origin"`
	Challenge         string `json:"challenge"`
	ClientDataJSON    string `json:"client_data_json"`
	AttestationObject string `json:"attestation_object"`
}

func loadAttestationVectors(t *testing.T) map[string]attestationVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/attestation/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var list []attestationVector
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]attestationVector, len(list))
	for _, v := range list {
		out[v.Name] = v
	}
	return out
}

func (v attestationVector) request(t *testing.T) AttestationRequest {
	t.Helper()
	b64 := base64.RawURLEncoding
	clientData, err := b64.DecodeString(v.ClientDataJSON)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := b64.DecodeString(v.AttestationObject)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := b64.DecodeString(v.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return AttestationRequest{
		AttestationObject: obj,
		ClientDataJSON:    clientData,
		RPID:              v.RPID,
		Origin:            v.Origin,
		Challenge:         challenge,
	}
}

func TestVerifyAttestationRealAuthenticators(t *testing.T) {
	vectors := loadAttestationVectors(t)

	tests := []struct {
		vector      string
		want        AttestationTrust
		wantErr     error
		wantAAGUID  string
		wantUV      bool
		wantRealAAG bool // AAGUID is non-zero
	}{
		{vector: "feitian_biopass_packed_x5c", want: AttestationTrustUnrooted, wantRealAAG: true},
		// Solo 2 registers an Ed25519 credential key, which a Soroban host cannot verify.
		{vector: "solokeys_solo2_packed_x5c", wantErr: ErrAttestationUnsupportedFormat},
		{vector: "virtual_authenticator_packed_x5c", want: AttestationTrustUnrooted, wantRealAAG: true},
		{vector: "macos_platform_packed_self", want: AttestationTrustSelf, wantRealAAG: true},
		{vector: "google_titan_none", want: AttestationTrustNone},
		{vector: "google_titan_fido_u2f", wantErr: ErrAttestationUnsupportedFormat},
		{vector: "packed_es512_self", wantErr: ErrAttestationUnsupportedFormat},
	}
	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			v, ok := vectors[tt.vector]
			if !ok {
				t.Fatalf("vector %q is missing from vectors.json", tt.vector)
			}
			got, err := VerifyAttestation(v.request(t))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Trust != tt.want {
				t.Fatalf("trust = %q, want %q", got.Trust, tt.want)
			}
			if got.HardwareBacked || got.AAGUIDAuthenticated {
				t.Fatalf("an attestation below rooted trust claimed hardware backing (%v) or an authenticated AAGUID (%v)",
					got.HardwareBacked, got.AAGUIDAuthenticated)
			}
			if (got.AAGUID != [16]byte{}) != tt.wantRealAAG {
				t.Fatalf("AAGUID %x, want a real one: %v", got.AAGUID, tt.wantRealAAG)
			}
			if len(got.PublicKeySEC1) != 65 || got.PublicKeySEC1[0] != 4 || got.PublicKey == nil {
				t.Fatalf("public key not returned in SEC1 form: %x", got.PublicKeySEC1)
			}
			if len(got.CredentialID) == 0 || !got.UserPresent {
				t.Fatalf("credential ID %x, UP %v", got.CredentialID, got.UserPresent)
			}
			if len(got.Proven) == 0 || len(got.Asserted) == 0 {
				t.Fatalf("proven %v / asserted %v: both must be reported", got.Proven, got.Asserted)
			}
		})
	}

	t.Run("none attestation is reported as proving nothing, not as a weak pass", func(t *testing.T) {
		got, err := VerifyAttestation(vectors["google_titan_none"].request(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Trust != AttestationTrustNone || !strings.Contains(strings.Join(got.Asserted, "\n"), "nothing about the authenticator") {
			t.Fatalf("trust %q, asserted %v", got.Trust, got.Asserted)
		}
		for _, p := range got.Proven {
			if strings.Contains(p, "authenticator model") || strings.Contains(p, "held the private key") {
				t.Fatalf("none attestation claims %q was proven", p)
			}
		}
	})

	t.Run("a chain that verifies to a supplied root is rooted", func(t *testing.T) {
		// The root comes from the vector's own x5c, which only shows the chain
		// check works. A real deployment supplies roots it obtained elsewhere.
		req := vectors["feitian_biopass_packed_x5c"].request(t)
		req.TrustRoots = rootFromX5C(t, req.AttestationObject)
		got, err := VerifyAttestation(req)
		if err != nil {
			t.Fatal(err)
		}
		if got.Trust != AttestationTrustRooted || !got.HardwareBacked || !got.AAGUIDAuthenticated {
			t.Fatalf("trust %q hardware %v aaguid %v", got.Trust, got.HardwareBacked, got.AAGUIDAuthenticated)
		}
	})

	t.Run("a supplied root that does not anchor the chain is refused, not downgraded", func(t *testing.T) {
		req := vectors["feitian_biopass_packed_x5c"].request(t)
		other := vectors["solokeys_solo2_packed_x5c"].request(t)
		req.TrustRoots = rootFromX5C(t, other.AttestationObject)
		if _, err := VerifyAttestation(req); !errors.Is(err, ErrAttestationInvalid) {
			t.Fatalf("err = %v, want ErrAttestationInvalid", err)
		}
	})

	t.Run("an expired certificate is refused under supplied roots", func(t *testing.T) {
		req := vectors["feitian_biopass_packed_x5c"].request(t)
		req.TrustRoots = rootFromX5C(t, req.AttestationObject)
		req.Now = req.Now.AddDate(3000, 0, 0)
		if _, err := VerifyAttestation(req); !errors.Is(err, ErrAttestationInvalid) {
			t.Fatalf("err = %v, want ErrAttestationInvalid", err)
		}
	})
}

func rootFromX5C(t *testing.T, obj []byte) *x509.CertPool {
	t.Helper()
	_, stmt, _, err := parseAttestationObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	x5c, _ := stmt.get("x5c")
	list := x5c.([]any)
	root, err := x509.ParseCertificate(list[len(list)-1].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool
}

// mutate returns a copy of obj with the byte at authData[offset] changed. The
// authenticator data is located inside the object by its bytes, so the
// attestation object's own framing is untouched.
func mutateAuthData(t *testing.T, obj []byte, offset int, fn func(byte) byte) []byte {
	t.Helper()
	_, _, authData, err := parseAttestationObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(obj, authData)
	if at < 0 {
		t.Fatal("authData not found in the attestation object")
	}
	out := append([]byte(nil), obj...)
	out[at+offset] = fn(out[at+offset])
	return out
}

func mutateBytes(t *testing.T, obj, field []byte, offset int) []byte {
	t.Helper()
	at := bytes.Index(obj, field)
	if at < 0 {
		t.Fatal("field not found in the attestation object")
	}
	out := append([]byte(nil), obj...)
	out[at+offset] ^= 0x01
	return out
}

func TestVerifyAttestationRejectsTampering(t *testing.T) {
	vectors := loadAttestationVectors(t)
	feitian := vectors["feitian_biopass_packed_x5c"]
	macos := vectors["macos_platform_packed_self"]
	titanNone := vectors["google_titan_none"]

	// Offsets into authenticator data (§6.1): rpIdHash 0-31, flags 32,
	// signCount 33-36, AAGUID 37-52, credentialIdLength 53-54, credentialId 55-.
	const (
		offRPID = 0
		offFlag = 32
		offCnt  = 33
		offAAG  = 37
		offCred = 55
	)

	type mutation struct {
		name    string
		vector  attestationVector
		mutate  func(t *testing.T, req *AttestationRequest)
		roots   bool
		wantErr error
		// wantText pins which check caught it, so a mutation cannot pass by
		// tripping an unrelated one.
		wantText string
	}
	flip := func(off int) func(*testing.T, *AttestationRequest) {
		return func(t *testing.T, req *AttestationRequest) {
			req.AttestationObject = mutateAuthData(t, req.AttestationObject, off, func(b byte) byte { return b ^ 0x01 })
		}
	}
	clearFlag := func(mask byte) func(*testing.T, *AttestationRequest) {
		return func(t *testing.T, req *AttestationRequest) {
			req.AttestationObject = mutateAuthData(t, req.AttestationObject, offFlag, func(b byte) byte { return b &^ mask })
		}
	}
	replaceClient := func(old, new string) func(*testing.T, *AttestationRequest) {
		return func(t *testing.T, req *AttestationRequest) {
			if !bytes.Contains(req.ClientDataJSON, []byte(old)) {
				t.Fatalf("client data does not contain %q", old)
			}
			req.ClientDataJSON = bytes.Replace(req.ClientDataJSON, []byte(old), []byte(new), 1)
		}
	}

	tests := []mutation{
		{name: "rpIdHash", vector: feitian, mutate: flip(offRPID), wantErr: ErrAttestationInvalid, wantText: "rpIdHash"},
		{name: "user presence flag", vector: feitian, mutate: clearFlag(flagUP), wantErr: ErrAttestationInvalid, wantText: "user presence"},
		{name: "attested credential data flag", vector: feitian, mutate: clearFlag(flagAT), wantErr: ErrAttestationInvalid, wantText: "AT"},
		{name: "signature counter (covered by the signature)", vector: feitian, mutate: flip(offCnt), wantErr: ErrAttestationInvalid, wantText: "signature does not verify"},
		{name: "AAGUID (covered by the signature)", vector: feitian, mutate: flip(offAAG), wantErr: ErrAttestationInvalid, wantText: "does not verify"},
		{name: "credential ID (covered by the signature)", vector: feitian, mutate: flip(offCred), wantErr: ErrAttestationInvalid, wantText: "signature does not verify"},
		{name: "self attestation: AAGUID", vector: macos, mutate: flip(offAAG), wantErr: ErrAttestationInvalid, wantText: "self attestation signature"},
		{name: "self attestation: credential ID", vector: macos, mutate: flip(offCred), wantErr: ErrAttestationInvalid, wantText: "self attestation signature"},
		{name: "attestation signature", vector: feitian, wantErr: ErrAttestationInvalid, wantText: "does not verify", mutate: func(t *testing.T, req *AttestationRequest) {
			_, stmt, _, _ := parseAttestationObject(req.AttestationObject)
			sig, _ := stmt.get("sig")
			s := sig.([]byte)
			req.AttestationObject = mutateBytes(t, req.AttestationObject, s, len(s)-1)
		}},
		{name: "self attestation signature", vector: macos, wantErr: ErrAttestationInvalid, wantText: "self attestation signature", mutate: func(t *testing.T, req *AttestationRequest) {
			_, stmt, _, _ := parseAttestationObject(req.AttestationObject)
			sig, _ := stmt.get("sig")
			s := sig.([]byte)
			req.AttestationObject = mutateBytes(t, req.AttestationObject, s, len(s)-1)
		}},
		{name: "leaf certificate under supplied roots", vector: feitian, roots: true, wantErr: ErrAttestationInvalid, wantText: "chain", mutate: func(t *testing.T, req *AttestationRequest) {
			_, stmt, _, _ := parseAttestationObject(req.AttestationObject)
			x5c, _ := stmt.get("x5c")
			leaf := x5c.([]any)[0].([]byte)
			req.AttestationObject = mutateBytes(t, req.AttestationObject, leaf, len(leaf)-1)
		}},
		{name: "statement format", vector: feitian, wantErr: ErrAttestationUnsupportedFormat, wantText: "qacked", mutate: func(t *testing.T, req *AttestationRequest) {
			req.AttestationObject = mutateBytes(t, req.AttestationObject, []byte("fmtfpacked"), 4)
		}},
		{name: "client data challenge", vector: feitian, wantErr: ErrAttestationInvalid, wantText: "challenge", mutate: func(t *testing.T, req *AttestationRequest) {
			req.Challenge = append([]byte(nil), req.Challenge...)
			req.Challenge[0] ^= 0x01
		}},
		{name: "client data type", vector: feitian, wantErr: ErrAttestationInvalid, wantText: "type", mutate: replaceClient("webauthn.create", "webauthn.get")},
		{name: "client data origin", vector: feitian, wantErr: ErrAttestationInvalid, wantText: "origin", mutate: func(t *testing.T, req *AttestationRequest) {
			req.Origin = "https://evil.example"
		}},
		{name: "client data bytes (their hash is signed)", vector: feitian, wantErr: ErrAttestationInvalid, wantText: "does not verify", mutate: func(t *testing.T, req *AttestationRequest) {
			req.ClientDataJSON = append(append([]byte(nil), req.ClientDataJSON...), ' ')
		}},
		{name: "relying party", vector: feitian, wantErr: ErrAttestationInvalid, wantText: "rpIdHash", mutate: func(t *testing.T, req *AttestationRequest) {
			req.RPID = "example.com"
		}},
		{name: "user verification required but absent", vector: titanNone, wantErr: ErrAttestationInvalid, wantText: "user verification", mutate: func(t *testing.T, req *AttestationRequest) {
			req.AttestationObject = mutateAuthData(t, req.AttestationObject, offFlag, func(b byte) byte { return b &^ flagUV })
			req.RequireUserVerification = true
		}},
		{name: "client data is not JSON", vector: feitian, wantErr: ErrAttestationMalformed, mutate: func(t *testing.T, req *AttestationRequest) {
			req.ClientDataJSON = []byte("not json")
		}},
		{name: "attestation object is not CBOR", vector: feitian, wantErr: ErrAttestationMalformed, mutate: func(t *testing.T, req *AttestationRequest) {
			req.AttestationObject = []byte{0xff, 0xff}
		}},
		{name: "attestation object has trailing bytes", vector: feitian, wantErr: ErrAttestationMalformed, wantText: "trailing", mutate: func(t *testing.T, req *AttestationRequest) {
			req.AttestationObject = append(append([]byte(nil), req.AttestationObject...), 0x00)
		}},
		{name: "authData truncated", vector: titanNone, wantErr: ErrAttestationMalformed, mutate: func(t *testing.T, req *AttestationRequest) {
			_, _, authData, _ := parseAttestationObject(req.AttestationObject)
			req.AttestationObject = cborObject("none", cborMapOf(), authData[:30])
		}},
		{name: "authData with trailing bytes", vector: titanNone, wantErr: ErrAttestationMalformed, wantText: "trailing", mutate: func(t *testing.T, req *AttestationRequest) {
			_, _, authData, _ := parseAttestationObject(req.AttestationObject)
			req.AttestationObject = cborObject("none", cborMapOf(), append(append([]byte(nil), authData...), 0x00))
		}},
		{name: "none statement that is not empty", vector: titanNone, wantErr: ErrAttestationInvalid, wantText: "must be empty", mutate: func(t *testing.T, req *AttestationRequest) {
			_, _, authData, _ := parseAttestationObject(req.AttestationObject)
			req.AttestationObject = cborObject("none", cborMapOf(cborText("alg"), cborInt(-7)), authData)
		}},
		{name: "attestation object with an extra member", vector: titanNone, wantErr: ErrAttestationMalformed, wantText: "exactly", mutate: func(t *testing.T, req *AttestationRequest) {
			_, _, authData, _ := parseAttestationObject(req.AttestationObject)
			req.AttestationObject = cborMapOf(
				cborText("fmt"), cborText("none"), cborText("attStmt"), cborMapOf(),
				cborText("authData"), cborBytes(authData), cborText("extra"), cborInt(1))
		}},
		{name: "packed ECDAA statement", vector: feitian, wantErr: ErrAttestationUnsupportedFormat, wantText: "ECDAA", mutate: func(t *testing.T, req *AttestationRequest) {
			_, _, authData, _ := parseAttestationObject(req.AttestationObject)
			req.AttestationObject = cborObject("packed", cborMapOf(cborText("alg"), cborInt(-7), cborText("sig"), cborBytes([]byte{1}), cborText("ecdaaKeyId"), cborBytes([]byte{1})), authData)
		}},
		{name: "packed statement with an unknown algorithm", vector: feitian, wantErr: ErrAttestationUnsupportedFormat, wantText: "-257", mutate: func(t *testing.T, req *AttestationRequest) {
			_, _, authData, _ := parseAttestationObject(req.AttestationObject)
			req.AttestationObject = cborObject("packed", cborMapOf(cborText("alg"), cborInt(-257), cborText("sig"), cborBytes([]byte{1})), authData)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.vector.request(t)
			// The untouched vector must pass first, so a failure below is
			// attributable to the mutation alone.
			if tt.roots {
				req.TrustRoots = rootFromX5C(t, req.AttestationObject)
			}
			if _, err := VerifyAttestation(req); err != nil {
				t.Fatalf("the unmodified vector does not verify: %v", err)
			}
			tt.mutate(t, &req)
			result, err := VerifyAttestation(req)
			if err == nil {
				t.Fatal("tampered attestation was accepted")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantText)
			}
			if result.PublicKey != nil || result.Trust != "" {
				t.Fatal("a rejected attestation returned a partial result")
			}
		})
	}

	t.Run("a missing expectation is refused", func(t *testing.T) {
		for _, clear := range []func(*AttestationRequest){
			func(r *AttestationRequest) { r.RPID = "" },
			func(r *AttestationRequest) { r.Origin = "" },
			func(r *AttestationRequest) { r.Challenge = nil },
		} {
			req := feitian.request(t)
			clear(&req)
			if _, err := VerifyAttestation(req); !errors.Is(err, ErrAttestationInvalid) {
				t.Fatalf("err = %v, want ErrAttestationInvalid", err)
			}
		}
	})
}

func TestVerifyAttestationPublicKeyIsOnTheCurve(t *testing.T) {
	req := loadAttestationVectors(t)["google_titan_none"].request(t)
	_, _, authData, err := parseAttestationObject(req.AttestationObject)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyAttestation(req)
	if err != nil {
		t.Fatal(err)
	}
	// Move the key's x coordinate off the curve; the none format has no
	// signature to catch it, so only the curve check can.
	at := bytes.Index(authData, res.PublicKeySEC1[1:33])
	if at < 0 {
		t.Fatal("public key x not found in authData")
	}
	bad := append([]byte(nil), authData...)
	for i := 0; i < 32; i++ {
		bad[at+i] = 0xff
	}
	req.AttestationObject = cborObject("none", cborMapOf(), bad)
	if _, err := VerifyAttestation(req); !errors.Is(err, ErrAttestationMalformed) {
		t.Fatalf("err = %v, want ErrAttestationMalformed", err)
	}
}

func TestVerifyAttestationRPIDHashIsSHA256(t *testing.T) {
	v := loadAttestationVectors(t)["feitian_biopass_packed_x5c"]
	req := v.request(t)
	_, _, authData, _ := parseAttestationObject(req.AttestationObject)
	want := sha256.Sum256([]byte("localhost"))
	if !bytes.Equal(authData[:32], want[:]) {
		t.Fatal("the vector's rpIdHash is not SHA-256(\"localhost\")")
	}
}

// Minimal CBOR encoding for building test inputs.

func cborHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func cborText(s string) []byte { return append(cborHead(3, len(s)), s...) }

func cborBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }

func cborInt(n int) []byte {
	if n >= 0 {
		return cborHead(0, n)
	}
	return cborHead(1, -1-n)
}

func cborMapOf(kv ...[]byte) []byte {
	out := cborHead(5, len(kv)/2)
	for _, b := range kv {
		out = append(out, b...)
	}
	return out
}

func cborObject(format string, stmt, authData []byte) []byte {
	return cborMapOf(cborText("fmt"), cborText(format), cborText("attStmt"), stmt, cborText("authData"), cborBytes(authData))
}

func TestDecodeCBORRefusesWhatItDoesNotNeed(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated argument", []byte{0x19, 0x01}},
		{"indefinite-length array", []byte{0x9f, 0xff}},
		{"indefinite-length byte string", []byte{0x5f, 0xff}},
		{"tag", []byte{0xc1, 0x00}},
		{"float", []byte{0xf9, 0x3c, 0x00}},
		{"undefined", []byte{0xf7}},
		{"byte string longer than the input", []byte{0x44, 0x01}},
		{"array header larger than the input", []byte{0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"map header larger than the input", []byte{0xb9, 0xff, 0xff}},
		{"unsigned beyond int64", []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"negative beyond int64", []byte{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"byte string as a map key", []byte{0xa1, 0x41, 0x00, 0x00}},
		{"duplicate map key", cborMapOf(cborText("a"), cborInt(1), cborText("a"), cborInt(2))},
		{"nesting past the limit", bytes.Repeat([]byte{0x81}, cborMaxDepth+3)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := decodeCBOR(tt.in); !errors.Is(err, errCBOR) {
				t.Fatalf("err = %v, want a CBOR error", err)
			}
		})
	}

	t.Run("accepted values", func(t *testing.T) {
		v, rest, err := decodeCBOR(append(cborMapOf(cborInt(-2), cborBytes([]byte{1}), cborText("k"), []byte{0xf5}), 0xaa))
		if err != nil || len(rest) != 1 {
			t.Fatalf("err %v rest %x", err, rest)
		}
		m := v.(cborMap)
		if b, _ := m.get(int64(-2)); !bytes.Equal(b.([]byte), []byte{1}) {
			t.Fatalf("map = %v", m)
		}
		if b, _ := m.get("k"); b != true {
			t.Fatalf("map = %v", m)
		}
	})
}
