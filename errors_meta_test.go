package soroauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestEverySentinelHasAProducingTest enforces a project rule that was being
// upheld by hand: every exported sentinel error must have at least one test
// that produces it.
//
// Why a meta-test rather than trusting review. A sentinel exists so a caller
// can branch on it with errors.Is. One that nothing produces is either dead —
// the code path was removed and the sentinel outlived it — or live and
// unproven, which is worse: callers write errors.Is against it and it never
// matches. Neither shows up in a diff, because adding a sentinel and adding a
// test for it are separate edits and only the first is obvious.
//
// How it reads "produces". It parses errors.go for the exported names in its
// var block, then parses every _test.go file in this package and collects every
// identifier mentioned. A sentinel named anywhere in a test counts. That is
// deliberately loose: the sentinels are asserted several ways here — directly
// with errors.Is, through a want field in a table, through a sentinel field —
// and a check that recognised only one shape would fail honest tests and push
// people to write worse ones.
//
// What it therefore does not prove: that the mention is a real assertion. It
// proves a sentinel is not forgotten, not that it is well tested. That is the
// honest limit, and it is the limit the rule it enforces also has.
func TestEverySentinelHasAProducingTest(t *testing.T) {
	sentinels := exportedSentinels(t, "errors.go")
	if len(sentinels) == 0 {
		t.Fatal("found no exported sentinels in errors.go; the parser below is probably wrong, " +
			"and a silently empty check is worse than no check")
	}

	mentioned := identifiersInTests(t, ".")

	var missing []string
	for _, name := range sentinels {
		if !mentioned[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these exported sentinels are produced by no test: %s\n"+
			"Each one needs a test that provokes the error and asserts errors.Is against it. "+
			"If a sentinel is no longer produced by any code path, delete it instead.",
			strings.Join(missing, ", "))
	}

	t.Logf("%d exported sentinels, all mentioned by at least one test", len(sentinels))
}

func TestSentinelValuesAndMessagesAreDistinct(t *testing.T) {
	sentinels := sentinelDeclarations(t, "errors.go")
	if len(sentinels) == 0 {
		t.Fatal("found no exported sentinels in errors.go; refusing a vacuous distinctness check")
	}

	values := map[string]error{
		"ErrSourceAccountCredentials":           ErrSourceAccountCredentials,
		"ErrUnsupportedCredentials":             ErrUnsupportedCredentials,
		"ErrNoMatchingCredentialNode":           ErrNoMatchingCredentialNode,
		"ErrDuplicateDelegate":                  ErrDuplicateDelegate,
		"ErrSignatureMismatch":                  ErrSignatureMismatch,
		"ErrMissingSigner":                      ErrMissingSigner,
		"ErrAlreadySigned":                      ErrAlreadySigned,
		"ErrInvalidExpiration":                  ErrInvalidExpiration,
		"ErrTooManySignatures":                  ErrTooManySignatures,
		"ErrDecodeLimit":                        ErrDecodeLimit,
		"ErrNoInvokeOperation":                  ErrNoInvokeOperation,
		"ErrUnsupportedEnvelope":                ErrUnsupportedEnvelope,
		"ErrUnsignedCredentialNode":             ErrUnsignedCredentialNode,
		"ErrDelegatePlanUnmatched":              ErrDelegatePlanUnmatched,
		"ErrNonceAlreadyReserved":               ErrNonceAlreadyReserved,
		"ErrWebAuthnMalformedJSON":              ErrWebAuthnMalformedJSON,
		"ErrWebAuthnMissingField":               ErrWebAuthnMissingField,
		"ErrWebAuthnMalformedField":             ErrWebAuthnMalformedField,
		"ErrWebAuthnTruncatedAuthenticatorData": ErrWebAuthnTruncatedAuthenticatorData,
		"ErrWebAuthnChallengeMismatch":          ErrWebAuthnChallengeMismatch,
		"ErrSignerAddressMismatch":              ErrSignerAddressMismatch,
		"ErrVaultUnauthorized":                  ErrVaultUnauthorized,
		"ErrVaultKeyNotFound":                   ErrVaultKeyNotFound,
		"ErrVaultKeyType":                       ErrVaultKeyType,
		"ErrLedgerUnavailable":                  ErrLedgerUnavailable,
		"ErrLedgerLocked":                       ErrLedgerLocked,
		"ErrLedgerWrongApp":                     ErrLedgerWrongApp,
		"ErrLedgerBlindSigningDisabled":         ErrLedgerBlindSigningDisabled,
		"ErrLedgerDenied":                       ErrLedgerDenied,
		"ErrAttestationMalformed":               ErrAttestationMalformed,
		"ErrAttestationInvalid":                 ErrAttestationInvalid,
		"ErrAttestationUnsupportedFormat":       ErrAttestationUnsupportedFormat,
		"ErrPolicyRefusal":                      ErrPolicyRefusal,
		"ErrSignerTransient":                    ErrSignerTransient,
		"ErrChainExhausted":                     ErrChainExhausted,
		"ErrQuorumNotMet":                       ErrQuorumNotMet,
		"ErrQuorumDisagreement":                 ErrQuorumDisagreement,
	}
	if len(values) != len(sentinels) {
		t.Fatalf("found %d sentinel declarations but %d actual values; update this check to cover every sentinel", len(sentinels), len(values))
	}

	seen := make(map[string]error, len(sentinels))
	for _, sentinel := range sentinels {
		value, ok := values[sentinel.name]
		if !ok {
			t.Errorf("sentinel %s has no actual value in the distinctness check", sentinel.name)
			continue
		}
		if value.Error() != sentinel.message {
			t.Errorf("sentinel %s value message %q differs from errors.go message %q", sentinel.name, value.Error(), sentinel.message)
		}
		for otherName, otherValue := range seen {
			if value == otherValue {
				t.Errorf("sentinels %s and %s share the same error value", sentinel.name, otherName)
			}
			if value.Error() == otherValue.Error() {
				t.Errorf("sentinels %s and %s share the message %q", sentinel.name, otherName, value.Error())
			}
		}
		seen[sentinel.name] = value
	}
}

type sentinelDeclaration struct {
	name    string
	message string
}

func sentinelDeclarations(t *testing.T, path string) []sentinelDeclaration {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var sentinels []sentinelDeclaration
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Values) != len(valueSpec.Names) {
				continue
			}
			for i, name := range valueSpec.Names {
				if !name.IsExported() || !strings.HasPrefix(name.Name, "Err") {
					continue
				}
				call, ok := valueSpec.Values[i].(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					t.Fatalf("sentinel %s is not initialized with errors.New(string)", name.Name)
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "New" {
					t.Fatalf("sentinel %s is not initialized with errors.New(string)", name.Name)
				}
				message, ok := call.Args[0].(*ast.BasicLit)
				if !ok || message.Kind != token.STRING {
					t.Fatalf("sentinel %s does not have a literal error message", name.Name)
				}
				decoded, err := strconv.Unquote(message.Value)
				if err != nil {
					t.Fatalf("decoding message for %s: %v", name.Name, err)
				}
				sentinels = append(sentinels, sentinelDeclaration{name: name.Name, message: decoded})
			}
		}
	}
	return sentinels
}

// exportedSentinels returns the exported error variables declared in path.
func exportedSentinels(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var names []string
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range valueSpec.Names {
				// Exported, and named as an error by convention. The Err
				// prefix is what the project uses and what callers look for.
				if name.IsExported() && strings.HasPrefix(name.Name, "Err") {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}

// identifiersInTests returns every identifier mentioned in the _test.go files
// of dir, including the external test package, since examples live there.
func identifiersInTests(t *testing.T, dir string) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	mentioned := map[string]bool{}
	seenAny := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		// This file is not evidence of anything: it names every sentinel by
		// construction, so counting it would make the check pass always.
		if name == "errors_meta_test.go" {
			continue
		}
		seenAny = true

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok {
				mentioned[ident.Name] = true
			}
			return true
		})
	}
	if !seenAny {
		t.Fatal("found no _test.go files to scan; the check would pass vacuously")
	}
	return mentioned
}
