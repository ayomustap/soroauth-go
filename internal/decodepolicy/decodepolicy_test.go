package decodepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes one Go source file into a fresh temp directory and returns
// that directory, so every case is measured against a file the test controls
// rather than against this repository's ever-changing tree.
func fixture(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(source), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return dir
}

// TestRoot_ReportsAnExportedFunctionThatDecodesDirectly is the case this
// package exists for. If this does not bite, the check is decoration.
func TestRoot_ReportsAnExportedFunctionThatDecodesDirectly(t *testing.T) {
	dir := fixture(t, `package fixture

import "github.com/stellar/go-stellar-sdk/xdr"

// Decode decodes an entry.
func Decode(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(result.Violations), result.Violations)
	}
	got := result.Violations[0]
	if got.Function != "Decode" {
		t.Errorf("Function = %q, want %q", got.Function, "Decode")
	}
	if got.Call != "xdr.SafeUnmarshalBase64" {
		t.Errorf("Call = %q, want %q", got.Call, "xdr.SafeUnmarshalBase64")
	}
	if strings.Join(got.Chain, " -> ") != "Decode" {
		t.Errorf("Chain = %v, want just the function itself", got.Chain)
	}
	if !strings.Contains(got.Position, "fixture.go:") {
		t.Errorf("Position = %q, want a file:line in the fixture", got.Position)
	}
	if !strings.Contains(got.String(), "Decode") {
		t.Errorf("String() does not name the function: %q", got.String())
	}
	// The caller's vacuous-pass guard counts entry points; a fixture that has
	// one must be counted, or that guard would fire on a clean tree.
	if result.EntryPoints != 1 {
		t.Errorf("EntryPoints = %d, want 1", result.EntryPoints)
	}
	if result.Packages != 1 {
		t.Errorf("Packages = %d, want 1", result.Packages)
	}
}

// TestRoot_FollowsAPackageLocalHelper proves "reaching" includes a helper, so
// an exported function cannot bypass the rule by moving the call one frame
// down, and that the report names the whole chain a reader has to look at.
func TestRoot_FollowsAPackageLocalHelper(t *testing.T) {
	dir := fixture(t, `package fixture

import "github.com/stellar/go-stellar-sdk/xdr"

// Decode decodes an entry by way of decodeInner.
func Decode(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	return decodeInner(encoded)
}

func decodeInner(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(result.Violations), result.Violations)
	}
	chain := strings.Join(result.Violations[0].Chain, " -> ")
	if chain != "Decode -> decodeInner" {
		t.Errorf("Chain = %q, want %q", chain, "Decode -> decodeInner")
	}
}

// TestRoot_BoundedDecodeIsNotAViolation pins the other half of the rule: the
// bounded call DecodeAuthorizationEntry makes must stay clean, or the check
// would forbid the fix it asks for.
func TestRoot_BoundedDecodeIsNotAViolation(t *testing.T) {
	dir := fixture(t, `package fixture

import "github.com/stellar/go-stellar-sdk/xdr"

// Decode decodes an entry with explicit options.
func Decode(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64WithOptions(encoded, &entry, xdr.DecodeOptions{MaxDepth: 64}); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("SafeUnmarshalBase64WithOptions was reported as unbounded: %v", result.Violations)
	}
}

// TestRoot_OtherPackagesUnmarshalIsNotAViolation guards the false positives
// that would make the check unusable: encoding/json and encoding/asn1 both
// have an Unmarshal, and neither decodes XDR.
func TestRoot_OtherPackagesUnmarshalIsNotAViolation(t *testing.T) {
	dir := fixture(t, `package fixture

import (
	"encoding/json"
)

// Decode decodes JSON, not XDR.
func Decode(data []byte) (map[string]string, error) {
	var out map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("json.Unmarshal was reported as an XDR decoder: %v", result.Violations)
	}
}

// TestRoot_AnAliasedImportIsStillCaught covers the file that renames the xdr
// package: the rule is about the decoder, not the name it was imported under.
func TestRoot_AnAliasedImportIsStillCaught(t *testing.T) {
	dir := fixture(t, `package fixture

import xdrtypes "github.com/stellar/go-stellar-sdk/xdr"

// Decode decodes an entry through an aliased import.
func Decode(encoded string) (xdrtypes.SorobanAuthorizationEntry, error) {
	var entry xdrtypes.SorobanAuthorizationEntry
	if err := xdrtypes.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdrtypes.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(result.Violations), result.Violations)
	}
	if result.Violations[0].Call != "xdrtypes.SafeUnmarshalBase64" {
		t.Errorf("Call = %q, want the aliased form", result.Violations[0].Call)
	}
}

// TestRoot_AllowanceIsExplicitAndConfined proves the escape hatch is opt-in
// and local: an annotated function is not reported, and neither is a caller
// that delegates to it, while an unannotated sibling still is.
func TestRoot_AllowanceIsExplicitAndConfined(t *testing.T) {
	dir := fixture(t, `package fixture

import "github.com/stellar/go-stellar-sdk/xdr"

// Allowed decodes an entry from a trusted source.
//
// decode-allow: the bytes come from this package's own encoder.
func Allowed(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}

// ViaAllowed calls the allowed function.
func ViaAllowed(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	return Allowed(encoded)
}

// NotAllowed decodes an entry with no allowance.
func NotAllowed(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want only NotAllowed: %v", len(result.Violations), result.Violations)
	}
	if result.Violations[0].Function != "NotAllowed" {
		t.Errorf("reported %q, want NotAllowed", result.Violations[0].Function)
	}
	if len(result.Allowances) != 1 {
		t.Fatalf("got %d allowances, want 1: %v", len(result.Allowances), result.Allowances)
	}
	if !strings.Contains(result.Allowances[0], "Allowed") {
		t.Errorf("allowance list does not name the allowed function: %v", result.Allowances)
	}
	if !strings.Contains(result.Allowances[0], "this package's own encoder") {
		t.Errorf("allowance list lost the reason: %v", result.Allowances)
	}
}

// TestRoot_UnexportedFunctionsAreNotEntryPoints keeps the rule about the
// public surface: an unexported function is not something a caller can reach,
// so it is not reported on its own.
func TestRoot_UnexportedFunctionsAreNotEntryPoints(t *testing.T) {
	dir := fixture(t, `package fixture

import "github.com/stellar/go-stellar-sdk/xdr"

func decode(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`)

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("an unexported function was reported: %v", result.Violations)
	}
	if result.EntryPoints != 0 {
		t.Errorf("EntryPoints = %d, want 0 (nothing exported)", result.EntryPoints)
	}
}

// TestRoot_SkipsNestedModule proves a directory holding its own go.mod is
// never descended into: it is a separate module whose public surface is
// checked by its own CI job, and folding it in here would report on a module
// this one does not own.
func TestRoot_SkipsNestedModule(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "go.mod"), []byte("module nested\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "nested.go"), []byte(`package nested

import "github.com/stellar/go-stellar-sdk/xdr"

// Decode decodes an entry.
func Decode(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}
`), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if result.Packages != 0 || result.EntryPoints != 0 || len(result.Violations) != 0 {
		t.Errorf("a nested module was not skipped: %+v", result)
	}
}

// TestRoot_EmptyDirectoryIsNotAnError proves directories holding no Go source
// are tolerated, so the walk does not need the caller to special-case them.
func TestRoot_EmptyDirectoryIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not go"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	result, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if result.Packages != 0 || result.EntryPoints != 0 {
		t.Errorf("a directory with no Go source was counted as a package: %+v", result)
	}
}
