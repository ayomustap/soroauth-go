package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/remote"
)

// defaultExecSignerTimeout bounds an external signer process when the caller
// does not pass --signer-timeout, so a wedged helper cannot hang the CLI.
const defaultExecSignerTimeout = 30 * time.Second

// Distinct sentinel errors for the failure modes of an exec-based external
// signer (#372): non-zero exit, timeout, and malformed output (plus explicit
// protocol refusal when the helper returns a well-formed error response).
var (
	errExecSignerExit            = errors.New("external signer exited non-zero")
	errExecSignerTimeout         = errors.New("external signer timed out")
	errExecSignerMalformedOutput = errors.New("external signer returned malformed output")
	errExecSignerRefused         = errors.New("external signer refused to sign")
)

// allowedHelperEnvVars is the strict allowlist of environment variables that
// may be inherited by the external signer subprocess. No SOROAUTH_* variable
// and no secret-bearing variable is ever included, and every value is
// additionally checked with looksLikeSecret before being passed.
var allowedHelperEnvVars = []string{
	"PATH",
	"HOME",
	"TMPDIR",
	"TMP",
	"TEMP",
	"TERM",
	"LANG",
	"LC_ALL",
	"USER",
	"LOGNAME",
	"SYSTEMROOT",
}

// sanitizeHelperEnv builds the environment slice for the external signer
// subprocess. It starts from an empty environment and copies only safe
// system variables from allowedHelperEnvVars whose values do not look like
// secrets, ensuring no secret is ever passed to the helper in the environment.
func sanitizeHelperEnv(getenv func(string) string) []string {
	if getenv == nil {
		getenv = os.Getenv
	}
	env := make([]string, 0, len(allowedHelperEnvVars))
	for _, key := range allowedHelperEnvVars {
		val := getenv(key)
		if val == "" {
			continue
		}
		if containsSecretToken(val) {
			continue
		}
		env = append(env, key+"="+val)
	}
	return env
}

// containsSecretToken reports whether s or any whitespace/delimiter-separated
// token inside s looks like a secret seed or key.
func containsSecretToken(s string) bool {
	if looksLikeSecret(s) {
		return true
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '=' || r == ':' || r == ';' || r == ','
	})
	for _, tok := range fields {
		if looksLikeSecret(tok) {
			return true
		}
	}
	return false
}

// execSigner implements soroauth.Signer by invoking an external program over
// stdin and stdout using the JSON message shapes defined in remote/protocol.go.
//
// It holds no secret: only the executable path, the target address, the
// execution timeout, and the sanitized environment builder.
type execSigner struct {
	command string
	address string
	timeout time.Duration
	env     []string
}

// newExecSigner constructs an execSigner after verifying that command is non-empty,
// does not contain any secret-shaped token, and timeout is positive.
func newExecSigner(command, address string, timeout time.Duration, getenv func(string) string) (*execSigner, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil, newErrorf(ExitUsageError, "--signer-cmd must not be empty")
	}
	if containsSecretToken(trimmed) {
		return nil, newErrorf(ExitUsageError,
			"--signer-cmd contains a secret-shaped value; pass only the path to the signer executable, never a secret")
	}
	if timeout <= 0 {
		return nil, newErrorf(ExitUsageError, "--signer-timeout must be greater than zero")
	}
	return &execSigner{
		command: trimmed,
		address: address,
		timeout: timeout,
		env:     sanitizeHelperEnv(getenv),
	}, nil
}

// withAddress returns a copy of s bound to addr, used when signing a single
// entry or batch where --for was omitted and the entry's own top-level address
// is unambiguous.
func (s *execSigner) withAddress(addr string) *execSigner {
	cp := *s
	cp.address = addr
	return &cp
}

// Address implements soroauth.Signer.
func (s *execSigner) Address() string {
	if s == nil {
		return ""
	}
	return s.address
}

// Sign implements soroauth.Signer by writing remote.Request as JSON to the
// helper's stdin, reading remote.Response from its stdout, and validating the
// returned signature ScVal before handing it back to AuthorizeEntry.
func (s *execSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("exec signer: %w", err)
	}
	if s == nil || s.address == "" {
		return xdr.ScVal{}, fmt.Errorf("exec signer: %w", soroauth.ErrMissingSigner)
	}

	encodedPreimage, err := xdr.MarshalBase64(preimage)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("exec signer: encoding the preimage: %w", err)
	}

	reqBytes, err := json.Marshal(remote.Request{
		Version:  remote.Version,
		Address:  s.address,
		Preimage: encodedPreimage,
		Payload:  hex.EncodeToString(payload[:]),
	})
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("exec signer: encoding the request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')

	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// The helper is executed directly with no command-line arguments and a
	// sanitized environment so no secret can ever be passed via argv or env.
	cmd := exec.CommandContext(callCtx, s.command)
	cmd.Env = s.env
	cmd.Stdin = bytes.NewReader(reqBytes)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		return xdr.ScVal{}, fmt.Errorf("%w after %s running %q", errExecSignerTimeout, s.timeout, s.command)
	}
	if errors.Is(callCtx.Err(), context.Canceled) {
		return xdr.ScVal{}, fmt.Errorf("exec signer: %w", callCtx.Err())
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			detail := strings.TrimSpace(stderrBuf.String())
			if containsSecretToken(detail) {
				detail = "[stderr redacted: contained secret-shaped token]"
			}
			if detail != "" {
				return xdr.ScVal{}, fmt.Errorf("%w (exit code %d): %s", errExecSignerExit, exitErr.ExitCode(), detail)
			}
			return xdr.ScVal{}, fmt.Errorf("%w (exit code %d)", errExecSignerExit, exitErr.ExitCode())
		}
		return xdr.ScVal{}, fmt.Errorf("%w: starting %q: %v", errExecSignerExit, s.command, runErr)
	}

	rawOut := stdoutBuf.Bytes()
	if int64(len(rawOut)) > remote.MaxRequestBytes {
		return xdr.ScVal{}, fmt.Errorf("%w: response exceeds maximum size (%d bytes)",
			errExecSignerMalformedOutput, remote.MaxRequestBytes)
	}
	if len(bytes.TrimSpace(rawOut)) == 0 {
		return xdr.ScVal{}, fmt.Errorf("%w: empty stdout (expected JSON response)", errExecSignerMalformedOutput)
	}

	decoder := json.NewDecoder(bytes.NewReader(rawOut))
	decoder.DisallowUnknownFields()
	var resp remote.Response
	if err := decoder.Decode(&resp); err != nil {
		return xdr.ScVal{}, fmt.Errorf("%w: invalid JSON response: %v", errExecSignerMalformedOutput, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return xdr.ScVal{}, fmt.Errorf("%w: unexpected trailing data after JSON response", errExecSignerMalformedOutput)
	}

	if resp.Version != remote.Version {
		return xdr.ScVal{}, fmt.Errorf("%w: unsupported protocol version %d (want %d)",
			errExecSignerMalformedOutput, resp.Version, remote.Version)
	}
	if resp.Error != "" && resp.Signature != "" {
		return xdr.ScVal{}, fmt.Errorf("%w: response sets both signature and error", errExecSignerMalformedOutput)
	}
	if resp.Error != "" {
		msg := resp.Error
		if containsSecretToken(msg) {
			msg = "[error redacted: contained secret-shaped token]"
		}
		return xdr.ScVal{}, fmt.Errorf("%w: %s", errExecSignerRefused, msg)
	}
	if resp.Signature == "" {
		return xdr.ScVal{}, fmt.Errorf("%w: response is missing signature field", errExecSignerMalformedOutput)
	}

	sig, err := validateSignatureScVal(resp.Signature, s.address, payload)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("%w: %v", errExecSignerMalformedOutput, err)
	}
	return sig, nil
}

// validateSignatureScVal decodes a base64 XDR ScVal returned by an external
// signer and verifies that it is well-formed before the CLI writes it into an
// authorization entry.
//
// Specifically:
//   - the string must be valid standard base64;
//   - the decoded bytes must unmarshal cleanly as an xdr.ScVal with no trailing bytes;
//   - the ScVal must not be an unsigned placeholder (ScvVoid or an empty ScvVec);
//   - scalar primitive types (integers, booleans, strings, symbols, errors, etc.)
//     that cannot represent a signature are rejected naming the type;
//   - for a classic account target (G…) — or any ScvVec carrying classic
//     {public_key, signature} map entries — the vector must hold between 1 and
//     MaxAccountSignatures (20) maps, each map must have keys sorted in the
//     canonical XDR order ("public_key" then "signature") with a 32-byte
//     public_key and a 64-byte signature, and each Ed25519 signature must
//     verify over payload;
//   - for a contract account target (C…), a non-empty ScvVec, ScvMap (with
//     sorted keys), or ScvBytes is accepted after structural validation.
func validateSignatureScVal(encoded, targetAddress string, payload [32]byte) (xdr.ScVal, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("signature is not valid base64: %w", err)
	}
	if len(raw) == 0 {
		return xdr.ScVal{}, fmt.Errorf("signature base64 decoded to zero bytes")
	}

	var sig xdr.ScVal
	if err := xdr.SafeUnmarshal(raw, &sig); err != nil {
		return xdr.ScVal{}, fmt.Errorf("signature is not valid ScVal XDR: %w", err)
	}

	var targetScAddr xdr.ScAddress
	hasTargetAddr := false
	if targetAddress != "" {
		if parsed, err := soroauth.ParseAddress(targetAddress); err == nil {
			targetScAddr = parsed
			hasTargetAddr = true
		}
	}
	isClassicAccount := hasTargetAddr && targetScAddr.Type == xdr.ScAddressTypeScAddressTypeAccount

	switch sig.Type {
	case xdr.ScValTypeScvVoid:
		return xdr.ScVal{}, fmt.Errorf("signature ScVal is ScvVoid (unsigned placeholder)")

	case xdr.ScValTypeScvVec:
		if sig.Vec == nil || *sig.Vec == nil || len(**sig.Vec) == 0 {
			return xdr.ScVal{}, fmt.Errorf("signature ScVal is an empty ScvVec (unsigned placeholder)")
		}
		entries := **sig.Vec
		if len(entries) > 20 {
			return xdr.ScVal{}, fmt.Errorf("signature vector has %d entries, exceeding maximum %d",
				len(entries), 20)
		}
		if isClassicAccount || looksLikeAccountSignatureVec(entries) {
			if err := validateAccountSignatureVec(entries, payload); err != nil {
				return xdr.ScVal{}, err
			}
		} else {
			for i, elem := range entries {
				if err := validateCustomScValElement(elem); err != nil {
					return xdr.ScVal{}, fmt.Errorf("signature vector element %d: %w", i, err)
				}
			}
		}
		return sig, nil

	case xdr.ScValTypeScvMap:
		if isClassicAccount {
			return xdr.ScVal{}, fmt.Errorf("classic account signature must be an ScvVec of {public_key, signature} maps, got ScvMap")
		}
		if sig.Map == nil || *sig.Map == nil || len(**sig.Map) == 0 {
			return xdr.ScVal{}, fmt.Errorf("signature ScVal is an empty ScvMap")
		}
		if err := validateMapKeysSorted(**sig.Map); err != nil {
			return xdr.ScVal{}, err
		}
		return sig, nil

	case xdr.ScValTypeScvBytes:
		if isClassicAccount {
			return xdr.ScVal{}, fmt.Errorf("classic account signature must be an ScvVec of {public_key, signature} maps, got ScvBytes")
		}
		if sig.Bytes == nil || len(*sig.Bytes) == 0 {
			return xdr.ScVal{}, fmt.Errorf("signature ScVal is empty ScvBytes")
		}
		return sig, nil

	default:
		return xdr.ScVal{}, fmt.Errorf("signature ScVal has unsupported type %s", sig.Type)
	}
}

// looksLikeAccountSignatureVec reports whether entries appears to be a classic
// account signature vector (any element is a map with symbol keys "public_key"
// or "signature").
func looksLikeAccountSignatureVec(entries []xdr.ScVal) bool {
	for _, elem := range entries {
		if elem.Type != xdr.ScValTypeScvMap || elem.Map == nil || *elem.Map == nil {
			return false
		}
		for _, kv := range **elem.Map {
			if kv.Key.Type == xdr.ScValTypeScvSymbol && kv.Key.Sym != nil {
				s := string(*kv.Key.Sym)
				if s == "public_key" || s == "signature" {
					return true
				}
			}
		}
	}
	return false
}

// validateAccountSignatureVec validates a classic account signature vector:
// every element must be a 2-entry map with sorted symbol keys "public_key"
// (32 bytes) and "signature" (64 bytes), and each Ed25519 signature must
// verify over payload.
func validateAccountSignatureVec(entries []xdr.ScVal, payload [32]byte) error {
	for i, elem := range entries {
		if elem.Type != xdr.ScValTypeScvMap || elem.Map == nil || *elem.Map == nil {
			return fmt.Errorf("signature vector entry %d is %s, want ScvMap", i, elem.Type)
		}
		mapEntries := **elem.Map
		if err := validateMapKeysSorted(mapEntries); err != nil {
			return fmt.Errorf("signature vector entry %d: %w", i, err)
		}
		if len(mapEntries) != 2 {
			return fmt.Errorf("signature vector entry %d has %d map fields, want 2 (public_key and signature)", i, len(mapEntries))
		}

		var pubKey, sigBytes []byte
		for _, kv := range mapEntries {
			if kv.Key.Type != xdr.ScValTypeScvSymbol || kv.Key.Sym == nil {
				return fmt.Errorf("signature vector entry %d has non-symbol map key %s", i, kv.Key.Type)
			}
			keyName := string(*kv.Key.Sym)
			if kv.Val.Type != xdr.ScValTypeScvBytes || kv.Val.Bytes == nil {
				return fmt.Errorf("signature vector entry %d field %q is %s, want ScvBytes", i, keyName, kv.Val.Type)
			}
			switch keyName {
			case "public_key":
				pubKey = *kv.Val.Bytes
			case "signature":
				sigBytes = *kv.Val.Bytes
			default:
				return fmt.Errorf("signature vector entry %d has unknown map field %q (want public_key and signature)", i, keyName)
			}
		}
		if len(pubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("signature vector entry %d public_key is %d bytes, want %d", i, len(pubKey), ed25519.PublicKeySize)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			return fmt.Errorf("signature vector entry %d signature is %d bytes, want %d", i, len(sigBytes), ed25519.SignatureSize)
		}
		if !ed25519.Verify(ed25519.PublicKey(pubKey), payload[:], sigBytes) {
			return fmt.Errorf("signature vector entry %d Ed25519 signature does not verify over payload", i)
		}
	}
	return nil
}

// validateMapKeysSorted checks that an ScMap's keys are strictly ordered when
// comparing symbol names (as required by Soroban host ScMap validation).
func validateMapKeysSorted(entries []xdr.ScMapEntry) error {
	for i := 1; i < len(entries); i++ {
		prev, curr := entries[i-1].Key, entries[i].Key
		if prev.Type == xdr.ScValTypeScvSymbol && curr.Type == xdr.ScValTypeScvSymbol &&
			prev.Sym != nil && curr.Sym != nil {
			if string(*prev.Sym) >= string(*curr.Sym) {
				return fmt.Errorf("signature map keys are not in sorted order (%q before %q)", *prev.Sym, *curr.Sym)
			}
		}
	}
	return nil
}

// validateCustomScValElement validates an element inside a custom contract
// signature vector.
func validateCustomScValElement(v xdr.ScVal) error {
	switch v.Type {
	case xdr.ScValTypeScvVoid, xdr.ScValTypeScvError:
		return fmt.Errorf("disallowed element type %s", v.Type)
	case xdr.ScValTypeScvMap:
		if v.Map == nil || *v.Map == nil {
			return fmt.Errorf("nil ScvMap element")
		}
		return validateMapKeysSorted(**v.Map)
	default:
		return nil
	}
}

// inferSingleEntryAddress extracts the top-level credential address of an
// entry when --for was not supplied for an external signer. If the entry
// carries delegates, --for is required because the target node is ambiguous.
func inferSingleEntryAddress(entry xdr.SorobanAuthorizationEntry) (string, error) {
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return "", nil
	}
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		return "", newErrorf(ExitUsageError,
			"--for is required with --signer-cmd when the entry carries delegates")
	}
	info, err := soroauth.Inspect(entry)
	if err != nil {
		return "", newErrorf(ExitUsageError, "inspecting entry address: %w", err)
	}
	if info.Address == "" {
		return "", newErrorf(ExitUsageError, "--for is required with --signer-cmd when the entry has no address")
	}
	return info.Address, nil
}
