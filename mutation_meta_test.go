package soroauth

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestEveryExportedEntryFunctionPreservesInput(t *testing.T) {
	functions := exportedEntryFunctions(t, ".")
	if len(functions) == 0 {
		t.Fatal("found no exported functions accepting SorobanAuthorizationEntry; refusing a vacuous mutation check")
	}

	var entry xdr.SorobanAuthorizationEntry
	for _, vector := range loadVectors(t) {
		if vector.Name != "delegates_unsorted_with_nested" {
			continue
		}
		if err := xdr.SafeUnmarshalBase64(vector.UnsignedEntryXDR, &entry); err != nil {
			t.Fatalf("decoding shared delegates fixture: %v", err)
		}
		break
	}
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		t.Fatal("shared delegates fixture is missing from the golden vectors")
	}
	address, err := FormatAddress(entry.Credentials.AddressWithDelegates.AddressCredentials.Address)
	if err != nil {
		t.Fatalf("formatting shared fixture address: %v", err)
	}
	validUntil := uint32(entry.Credentials.AddressWithDelegates.AddressCredentials.SignatureExpirationLedger) + 1
	flag := true
	signer := SignerFunc(address, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		return xdr.ScVal{Type: xdr.ScValTypeScvBool, B: &flag}, nil
	})

	checks := map[string]func(xdr.SorobanAuthorizationEntry){
		"Analyze": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = Analyze(entry, nil)
		},
		"AnalyzeWithCurrentLedger": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = AnalyzeWithCurrentLedger(context.Background(), entry, &RiskConfig{CurrentLedger: 1}, nil)
		},
		"AuthorizeAll": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, []Signer{signer}, validUntil, "Test SDF Network ; September 2015")
		},
		"AuthorizeBatch": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = AuthorizeBatch(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, []Signer{signer}, validUntil, "Test SDF Network ; September 2015")
		},
		"AuthorizeEntry": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = AuthorizeEntry(context.Background(), entry, signer, validUntil, "Test SDF Network ; September 2015")
		},
		"DiffEntries": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = DiffEntries(entry, entry)
		},
		"Inspect": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = Inspect(entry)
		},
		"NewCoordinator": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = NewCoordinator(entry, validUntil, "Test SDF Network ; September 2015")
		},
		"Preimage": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = Preimage(entry, validUntil, "Test SDF Network ; September 2015")
		},
		"PlannedTree.Wrap": func(entry xdr.SorobanAuthorizationEntry) {
			plan := &PlannedTree{ValidUntilLedger: validUntil}
			_, _ = plan.Wrap(entry, nil)
		},
		"UpgradeToV2": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = UpgradeToV2(entry)
		},
		"ValidateDelegateOrder": func(entry xdr.SorobanAuthorizationEntry) {
			_ = ValidateDelegateOrder(entry)
		},
		"VerifyEntry": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = VerifyEntry(entry, "Test SDF Network ; September 2015")
		},
		"VerifyEntryContext": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = VerifyEntryContext(context.Background(), entry, "Test SDF Network ; September 2015")
		},
		"VerifyAll": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = VerifyAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, "Test SDF Network ; September 2015")
		},
		"WithDelegates": func(entry xdr.SorobanAuthorizationEntry) {
			_, _ = WithDelegates(entry, validUntil, nil, nil)
		},
	}

	discovered := make(map[string]bool, len(functions))
	for _, name := range functions {
		discovered[name] = true
		check, ok := checks[name]
		if !ok {
			t.Errorf("exported function %s accepts SorobanAuthorizationEntry but has no mutation check", name)
			continue
		}
		before, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("encoding fixture before %s: %v", name, err)
		}
		check(entry)
		after, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("encoding fixture after %s: %v", name, err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("%s mutated its input entry", name)
		}
	}
	for name := range checks {
		if !discovered[name] {
			t.Errorf("mutation check for %s no longer matches an exported entry-taking function", name)
		}
	}
}

func exportedEntryFunctions(t *testing.T, dir string) []string {
	t.Helper()

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var names []string
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, file.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, decl := range parsed.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || !function.Name.IsExported() || function.Type.Params == nil {
				continue
			}
			hasEntry := false
			ast.Inspect(function.Type.Params, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "SorobanAuthorizationEntry" {
					if packageName, ok := selector.X.(*ast.Ident); ok && packageName.Name == "xdr" {
						hasEntry = true
					}
				}
				return true
			})
			if hasEntry {
				name := function.Name.Name
				if function.Recv != nil {
					name = receiverName(function.Recv.List[0].Type) + "." + name
				}
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func receiverName(expression ast.Expr) string {
	for {
		pointer, ok := expression.(*ast.StarExpr)
		if !ok {
			break
		}
		expression = pointer.X
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	return "unknown receiver"
}
