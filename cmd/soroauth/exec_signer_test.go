package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/remote"
)

// writeHelperScript writes an executable shell script to a temporary directory
// and returns its path.
func writeHelperScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "signer-helper.sh")
	script := "#!/usr/bin/env sh\nset -eu\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing helper script: %v", err)
	}
	return path
}

// validAccountSigBase64 computes a valid base64 XDR ScVal signature for kp over
// the given entry, expiration, and networkPassphrase.
func validAccountSigBase64(t *testing.T, entry xdr.SorobanAuthorizationEntry, expiration uint32, passphrase string, label string) (string, xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	kp := vectorKeypair(t, label)
	signer := soroauth.NewEd25519Signer(kp)
	preimage, err := soroauth.Preimage(entry, expiration, passphrase)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	scVal, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := scVal.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw), preimage, payload
}

// TestExecSignerMatchesGoldenVectorAndVerifiesProtocol asserts that --signer-cmd
// passes the exact remote.Request JSON (version, address, preimage, payload) on
// stdin, reads remote.Response from stdout, and produces the golden vector's
// signed entry.
func TestExecSignerMatchesGoldenVectorAndVerifiesProtocol(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	entry, err := soroauth.DecodeAuthorizationEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("DecodeAuthorizationEntry: %v", err)
	}
	kp := vectorKeypair(t, "soroauth-vector-signer-1")
	sigB64, wantPreimage, wantPayload := validAccountSigBase64(
		t, entry, 1234567, "Test SDF Network ; September 2015", "soroauth-vector-signer-1")
	wantPreimageB64, err := xdr.MarshalBase64(wantPreimage)
	if err != nil {
		t.Fatalf("MarshalBase64 preimage: %v", err)
	}
	wantPayloadHex := hex.EncodeToString(wantPayload[:])

	capturedReqFile := filepath.Join(t.TempDir(), "captured_request.json")
	respBytes, err := json.Marshal(remote.Response{
		Version:   remote.Version,
		Signature: sigB64,
	})
	if err != nil {
		t.Fatalf("Marshal response: %v", err)
	}

	helper := writeHelperScript(t, `cat > "`+capturedReqFile+`"
printf '%s\n' '`+string(respBytes)+`'`)

	// Run without --for (address inferred from the single entry) and with --for.
	for _, extraArgs := range [][]string{
		nil,
		{"--for", kp.Address()},
	} {
		args := []string{
			"sign",
			"--entry", v.UnsignedEntryXDR,
			"--valid-until", "1234567",
			"--network", "testnet",
			"--signer-cmd", helper,
		}
		args = append(args, extraArgs...)

		stdout, stderr, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("sign with --signer-cmd failed: %v (stderr: %s)", err, stderr)
		}
		signedVector := loadFullVector(t, "v2_single_testnet")
		if got := strings.TrimSpace(stdout); got != signedVector {
			t.Errorf("signed entry differs from golden vector\n want %s\n  got %s", signedVector, got)
		}

		// Inspect the captured stdin request to prove the protocol contract.
		rawReq, err := os.ReadFile(capturedReqFile)
		if err != nil {
			t.Fatalf("reading captured stdin request: %v", err)
		}
		var gotReq remote.Request
		if err := json.Unmarshal(rawReq, &gotReq); err != nil {
			t.Fatalf("captured stdin is not a valid remote.Request: %v\nraw: %s", err, rawReq)
		}
		if gotReq.Version != remote.Version {
			t.Errorf("request version = %d, want %d", gotReq.Version, remote.Version)
		}
		if gotReq.Address != kp.Address() {
			t.Errorf("request address = %q, want %q", gotReq.Address, kp.Address())
		}
		if gotReq.Preimage != wantPreimageB64 {
			t.Errorf("request preimage = %q, want %q", gotReq.Preimage, wantPreimageB64)
		}
		if gotReq.Payload != wantPayloadHex {
			t.Errorf("request payload = %q, want %q", gotReq.Payload, wantPayloadHex)
		}
	}
}

// TestExecSignerThreeDistinctErrors proves the acceptance criterion that the
// helper's non-zero exit, timeout, and malformed output are three distinct
// errors.
func TestExecSignerThreeDistinctErrors(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	exitHelper := writeHelperScript(t, `cat >/dev/null
echo "hardware token disconnected" >&2
exit 17`)

	timeoutHelper := writeHelperScript(t, `cat >/dev/null
sleep 5`)

	malformedHelper := writeHelperScript(t, `cat >/dev/null
printf 'not valid json\n'`)

	_, _, exitErr := runCLI(t, "sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--signer-cmd", exitHelper)
	if exitErr == nil {
		t.Fatal("expected error for non-zero exit helper")
	}

	_, _, timeoutErr := runCLI(t, "sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--signer-cmd", timeoutHelper,
		"--signer-timeout", "50ms")
	if timeoutErr == nil {
		t.Fatal("expected error for timed-out helper")
	}

	_, _, malformedErr := runCLI(t, "sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--signer-cmd", malformedHelper)
	if malformedErr == nil {
		t.Fatal("expected error for malformed output helper")
	}

	// Verify each error matches its own sentinel and NEITHER of the other two.
	if !errors.Is(exitErr, errExecSignerExit) {
		t.Errorf("exitErr %q does not wrap errExecSignerExit", exitErr)
	}
	if errors.Is(exitErr, errExecSignerTimeout) || errors.Is(exitErr, errExecSignerMalformedOutput) {
		t.Errorf("exitErr %q matched timeout or malformed sentinel", exitErr)
	}
	if !strings.Contains(exitErr.Error(), "exit code 17") || !strings.Contains(exitErr.Error(), "hardware token disconnected") {
		t.Errorf("exitErr %q missing exit code or stderr detail", exitErr)
	}

	if !errors.Is(timeoutErr, errExecSignerTimeout) {
		t.Errorf("timeoutErr %q does not wrap errExecSignerTimeout", timeoutErr)
	}
	if errors.Is(timeoutErr, errExecSignerExit) || errors.Is(timeoutErr, errExecSignerMalformedOutput) {
		t.Errorf("timeoutErr %q matched exit or malformed sentinel", timeoutErr)
	}

	if !errors.Is(malformedErr, errExecSignerMalformedOutput) {
		t.Errorf("malformedErr %q does not wrap errExecSignerMalformedOutput", malformedErr)
	}
	if errors.Is(malformedErr, errExecSignerExit) || errors.Is(malformedErr, errExecSignerTimeout) {
		t.Errorf("malformedErr %q matched exit or timeout sentinel", malformedErr)
	}
}

// TestExecSignerValidatesReturnedScVal proves that the returned signature is
// validated as well-formed before being written into the entry, and that every
// malformed response produces an error naming what was wrong.
func TestExecSignerValidatesReturnedScVal(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	entry, err := soroauth.DecodeAuthorizationEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("DecodeAuthorizationEntry: %v", err)
	}
	kp := vectorKeypair(t, "soroauth-vector-signer-1")
	wrongKP := vectorKeypair(t, "soroauth-vector-delegate-3")

	encodeScVal := func(val xdr.ScVal) string {
		raw, err := val.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}

	voidB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvVoid})
	emptyVec := xdr.ScVec{}
	emptyVecPtr := &emptyVec
	emptyVecB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &emptyVecPtr})
	u32Val := xdr.Uint32(42)
	u32B64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &u32Val})

	// Unsorted map keys ("signature" before "public_key")
	symSig := xdr.ScSymbol("signature")
	symPub := xdr.ScSymbol("public_key")
	pubBytes := xdr.ScBytes(make([]byte, ed25519.PublicKeySize))
	sigBytes := xdr.ScBytes(make([]byte, ed25519.SignatureSize))
	unsortedMap := xdr.ScMap{
		{
			Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symSig},
			Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &sigBytes},
		},
		{
			Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symPub},
			Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &pubBytes},
		},
	}
	unsortedMapPtr := &unsortedMap
	unsortedVec := xdr.ScVec{{Type: xdr.ScValTypeScvMap, Map: &unsortedMapPtr}}
	unsortedVecPtr := &unsortedVec
	unsortedB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &unsortedVecPtr})

	// Wrong public_key length (16 bytes instead of 32)
	shortPub := xdr.ScBytes(make([]byte, 16))
	shortPubMap := xdr.ScMap{
		{
			Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symPub},
			Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &shortPub},
		},
		{
			Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symSig},
			Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &sigBytes},
		},
	}
	shortPubMapPtr := &shortPubMap
	shortPubVec := xdr.ScVec{{Type: xdr.ScValTypeScvMap, Map: &shortPubMapPtr}}
	shortPubVecPtr := &shortPubVec
	shortPubB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &shortPubVecPtr})

	// Wrong Ed25519 signature bytes (valid lengths, wrong signature over payload)
	badEd25519Sig, _, _ := validAccountSigBase64(
		t, entry, 9999999, "Test SDF Network ; September 2015", "soroauth-vector-signer-1")
	_ = wrongKP

	cases := []struct {
		name       string
		stdoutText string
		wantReason string
	}{
		{
			name:       "empty stdout",
			stdoutText: "",
			wantReason: "empty stdout",
		},
		{
			name:       "unknown JSON field",
			stdoutText: `{"version":1,"signature":"` + voidB64 + `","extra":true}`,
			wantReason: "invalid JSON response",
		},
		{
			name:       "wrong protocol version",
			stdoutText: `{"version":2,"signature":"` + voidB64 + `"}`,
			wantReason: "unsupported protocol version 2",
		},
		{
			name:       "missing signature and error",
			stdoutText: `{"version":1}`,
			wantReason: "missing signature field",
		},
		{
			name:       "both signature and error set",
			stdoutText: `{"version":1,"signature":"` + voidB64 + `","error":"denied"}`,
			wantReason: "sets both signature and error",
		},
		{
			name:       "invalid base64 signature",
			stdoutText: `{"version":1,"signature":"!!!not-base64!!!"}`,
			wantReason: "signature is not valid base64",
		},
		{
			name:       "invalid XDR bytes",
			stdoutText: `{"version":1,"signature":"` + base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff, 0xff}) + `"}`,
			wantReason: "signature is not valid ScVal XDR",
		},
		{
			name:       "ScvVoid placeholder",
			stdoutText: `{"version":1,"signature":"` + voidB64 + `"}`,
			wantReason: "ScvVoid",
		},
		{
			name:       "empty ScvVec placeholder",
			stdoutText: `{"version":1,"signature":"` + emptyVecB64 + `"}`,
			wantReason: "empty ScvVec",
		},
		{
			name:       "scalar ScvU32 instead of signature",
			stdoutText: `{"version":1,"signature":"` + u32B64 + `"}`,
			wantReason: "unsupported type ScValTypeScvU32",
		},
		{
			name:       "unsorted map keys in signature",
			stdoutText: `{"version":1,"signature":"` + unsortedB64 + `"}`,
			wantReason: "not in sorted order",
		},
		{
			name:       "wrong public_key byte length",
			stdoutText: `{"version":1,"signature":"` + shortPubB64 + `"}`,
			wantReason: "public_key is 16 bytes, want 32",
		},
		{
			name:       "Ed25519 signature does not verify over payload",
			stdoutText: `{"version":1,"signature":"` + badEd25519Sig + `"}`,
			wantReason: "Ed25519 signature does not verify over payload",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			helper := writeHelperScript(t, `cat >/dev/null
printf '%s' '`+tc.stdoutText+`'`)

			stdout, _, err := runCLI(t, "sign",
				"--entry", v.UnsignedEntryXDR,
				"--valid-until", "1234567",
				"--network", "testnet",
				"--for", kp.Address(),
				"--signer-cmd", helper)
			if err == nil {
				t.Fatalf("expected error for %s, but sign succeeded with stdout: %s", tc.name, stdout)
			}
			if !errors.Is(err, errExecSignerMalformedOutput) {
				t.Errorf("error %q does not wrap errExecSignerMalformedOutput", err)
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Errorf("error %q does not name what was wrong (%q)", err.Error(), tc.wantReason)
			}
			if stdout != "" {
				t.Errorf("expected no signed entry on stdout when validation fails, got: %q", stdout)
			}
		})
	}
}

// TestExecSignerNeverPassesSecretsInArgsOrEnv proves that no secret is passed
// to the helper on the command line or in the environment, and that passing a
// secret-shaped string to --signer-cmd is refused without echoing it.
func TestExecSignerNeverPassesSecretsInArgsOrEnv(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	entry, err := soroauth.DecodeAuthorizationEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("DecodeAuthorizationEntry: %v", err)
	}
	kp := vectorKeypair(t, "soroauth-vector-signer-1")
	secretSeed := kp.Seed()
	sigB64, _, _ := validAccountSigBase64(
		t, entry, 1234567, "Test SDF Network ; September 2015", "soroauth-vector-signer-1")

	dumpFile := filepath.Join(t.TempDir(), "helper_env_and_args.txt")
	respBytes, _ := json.Marshal(remote.Response{
		Version:   remote.Version,
		Signature: sigB64,
	})

	helper := writeHelperScript(t, `cat >/dev/null
{
  echo "ARGS:$*"
  env
} > "`+dumpFile+`"
printf '%s\n' '`+string(respBytes)+`'`)

	// Inject secrets into the CLI environment, including in secret-named vars
	// and even in an allowed var (USER), and verify none reach the subprocess.
	_, _, err = runCLIEnv(t, map[string]string{
		"SEED":                  secretSeed,
		"SOROAUTH_SECRET_ENV":   "SEED",
		"SECRET_KEY":            secretSeed,
		"AWS_SECRET_ACCESS_KEY": "SNOTAREALSEEDATALL",
		"USER":                  secretSeed,
		"PATH":                  os.Getenv("PATH"),
	}, "sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--signer-cmd", helper)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	dumpBytes, err := os.ReadFile(dumpFile)
	if err != nil {
		t.Fatalf("reading helper dump: %v", err)
	}
	dump := string(dumpBytes)
	for _, forbidden := range []string{secretSeed, "SNOTAREALSEEDATALL", "SOROAUTH_SECRET_ENV", "AWS_SECRET_ACCESS_KEY"} {
		if strings.Contains(dump, forbidden) {
			t.Errorf("helper environment or args leaked %q:\n%s", forbidden, dump)
		}
	}
	if !strings.Contains(dump, "ARGS:\n") {
		t.Errorf("expected empty helper args, got:\n%s", dump)
	}

	t.Run("refuses secret passed on --signer-cmd without echoing it", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, "sign",
			"--entry", v.UnsignedEntryXDR,
			"--valid-until", "1234567",
			"--network", "testnet",
			"--signer-cmd", secretSeed)
		if err == nil {
			t.Fatal("expected error when passing a seed to --signer-cmd")
		}
		if ExitCode(err) != ExitUsageError {
			t.Errorf("exit code = %d, want %d", ExitCode(err), ExitUsageError)
		}
		for stream, text := range map[string]string{
			"stdout": stdout, "stderr": stderr, "error": err.Error(),
		} {
			if strings.Contains(text, secretSeed) {
				t.Errorf("%s leaked secret seed: %q", stream, text)
			}
		}
	})

	t.Run("refuses --secret-env and --signer-cmd together", func(t *testing.T) {
		_, _, err := runCLIEnv(t, map[string]string{"SEED": secretSeed},
			"sign",
			"--entry", v.UnsignedEntryXDR,
			"--valid-until", "1234567",
			"--network", "testnet",
			"--secret-env", "SEED",
			"--signer-cmd", helper)
		if err == nil {
			t.Fatal("expected error when both --secret-env and --signer-cmd are given")
		}
		if ExitCode(err) != ExitUsageError {
			t.Errorf("exit code = %d, want %d", ExitCode(err), ExitUsageError)
		}
	})

	t.Run("helper refusal maps to ExitSigningRefusal", func(t *testing.T) {
		refuseHelper := writeHelperScript(t, `cat >/dev/null
printf '{"version":1,"error":"user rejected signing request on device"}\n'`)
		_, _, err := runCLI(t, "sign",
			"--entry", v.UnsignedEntryXDR,
			"--valid-until", "1234567",
			"--network", "testnet",
			"--signer-cmd", refuseHelper)
		if err == nil {
			t.Fatal("expected error when helper refuses")
		}
		if ExitCode(err) != ExitSigningRefusal {
			t.Errorf("exit code = %d, want %d (ExitSigningRefusal)", ExitCode(err), ExitSigningRefusal)
		}
		if !errors.Is(err, errExecSignerRefused) {
			t.Errorf("expected errExecSignerRefused, got %v", err)
		}
	})

	t.Run("newExecSigner unit checks", func(t *testing.T) {
		if _, err := newExecSigner("", "GABC", time.Second, nil); err == nil {
			t.Error("expected error for empty command")
		}
		if _, err := newExecSigner("/bin/true", "GABC", 0, nil); err == nil {
			t.Error("expected error for zero timeout")
		}
	})
}

func TestValidateSignatureScValContractShapesAndAddressInference(t *testing.T) {
	var payload [32]byte
	classicAddr := vectorKeypair(t, "soroauth-vector-signer-1").Address()
	encodeScVal := func(v xdr.ScVal) string {
		b, err := v.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}

	// ScvBytes is accepted for a contract address (empty target) and rejected for a classic account.
	rawBytes := xdr.ScBytes{1, 2, 3, 4}
	bytesB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &rawBytes})
	if _, err := validateSignatureScVal(bytesB64, "", payload); err != nil {
		t.Fatalf("unexpected error for contract ScvBytes: %v", err)
	}
	if _, err := validateSignatureScVal(bytesB64, classicAddr, payload); err == nil {
		t.Fatal("expected error for classic account with ScvBytes")
	}
	emptyBytes := xdr.ScBytes{}
	emptyBytesB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &emptyBytes})
	if _, err := validateSignatureScVal(emptyBytesB64, "", payload); err == nil {
		t.Fatal("expected error for empty ScvBytes")
	}

	// ScvMap with sorted keys is accepted for a contract address and rejected for a classic account.
	symA := xdr.ScSymbol("a")
	symB := xdr.ScSymbol("b")
	sortedMap := xdr.ScMap{
		{Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symA}, Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &rawBytes}},
		{Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symB}, Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &rawBytes}},
	}
	sortedMapPtr := &sortedMap
	mapB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &sortedMapPtr})
	if _, err := validateSignatureScVal(mapB64, "", payload); err != nil {
		t.Fatalf("unexpected error for sorted contract ScvMap: %v", err)
	}
	if _, err := validateSignatureScVal(mapB64, classicAddr, payload); err == nil {
		t.Fatal("expected error for classic account with ScvMap")
	}
	emptyMap := xdr.ScMap{}
	emptyMapPtr := &emptyMap
	emptyMapB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &emptyMapPtr})
	if _, err := validateSignatureScVal(emptyMapB64, "", payload); err == nil {
		t.Fatal("expected error for empty ScvMap")
	}

	// Custom contract ScvVec with valid and invalid elements.
	customVec := xdr.ScVec{
		{Type: xdr.ScValTypeScvMap, Map: &sortedMapPtr},
		{Type: xdr.ScValTypeScvBytes, Bytes: &rawBytes},
	}
	customVecPtr := &customVec
	customVecB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &customVecPtr})
	if _, err := validateSignatureScVal(customVecB64, "", payload); err != nil {
		t.Fatalf("unexpected error for custom contract ScvVec: %v", err)
	}
	badCustomVec := xdr.ScVec{{Type: xdr.ScValTypeScvVoid}}
	badCustomVecPtr := &badCustomVec
	badCustomVecB64 := encodeScVal(xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &badCustomVecPtr})
	if _, err := validateSignatureScVal(badCustomVecB64, "", payload); err == nil {
		t.Fatal("expected error for ScvVoid element inside custom ScvVec")
	}

	// inferSingleEntryAddress refuses delegates arm without --for, and accepts source_account.
	delEntry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates},
	}
	if _, err := inferSingleEntryAddress(delEntry); err == nil {
		t.Fatal("expected error when inferring single address on delegates entry")
	}
	srcEntry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount},
	}
	if addr, err := inferSingleEntryAddress(srcEntry); err != nil || addr != "" {
		t.Fatalf("expected empty address and nil error for source_account, got %q, %v", addr, err)
	}
}
