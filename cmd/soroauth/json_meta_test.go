package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type jsonCommandCase struct {
	success []string
	failure []string
	env     map[string]string
}

func TestEveryCLICommandHasJSONSuccessAndFailure(t *testing.T) {
	vector := loadVector(t, "v2_single_testnet")
	delegatesVector := loadVector(t, "delegates_from_legacy")
	fixtures := loadRPCFixtures(t)
	simulateRPC := newFakeRPC(t, fixtures)
	submitRPC := newFakeRPC(t, fixtures)

	doctorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer doctorServer.Close()

	signer := vectorKeypair(t, "soroauth-vector-signer-1")
	payer := testPayer(t)
	delegate := delegatesVector.Delegates[0].Address
	entries := signedVectorEntries(t)
	simulateEnvelope := envelopeWithEntries(t, testPayerAddress(t), "1")
	submitEnvelope := envelopeWithEntries(t, testPayerAddress(t), "1", entries...)
	wasmArtifact := writeArtifact(t, 64)

	cases := map[string]jsonCommandCase{
		"payload": {
			success: []string{"--entry", vector.UnsignedEntryXDR, "--valid-until", "1234567", "--network", "testnet"},
			failure: []string{"--entry", "not-base64", "--valid-until", "1234567", "--network", "testnet"},
		},
		"sign": {
			success: []string{"--entry", vector.UnsignedEntryXDR, "--valid-until", "1234567", "--network", "testnet", "--secret-env", "SEED"},
			failure: []string{"--entry", "not-base64", "--valid-until", "1234567", "--network", "testnet", "--secret-env", "SEED"},
			env:     map[string]string{"SEED": signer.Seed()},
		},
		"simulate": {
			success: []string{"--entry", simulateEnvelope, "--rpc-url", simulateRPC.server.URL},
			failure: []string{"--entry", "not-base64", "--rpc-url", "http://127.0.0.1:0"},
		},
		"submit": {
			success: []string{"--entry", submitEnvelope, "--network", "testnet", "--secret-env", "SEED", "--rpc-url", submitRPC.server.URL},
			failure: []string{"--entry", "not-base64", "--network", "testnet", "--secret-env", "SEED", "--rpc-url", "http://127.0.0.1:0"},
			env:     map[string]string{"SEED": payer.Seed()},
		},
		"delegates": {
			success: []string{"--entry", delegatesVector.PreWrapEntryXDR, "--valid-until", "1234567", "--delegate", delegate},
			failure: []string{"--entry", vector.UnsignedEntryXDR, "--valid-until", "1234567", "--delegate", delegate, "--delegate", delegate},
		},
		"inspect": {
			success: []string{"--entry", vector.UnsignedEntryXDR},
			failure: []string{"--entry", "not-base64"},
		},
		"tree": {
			success: []string{"--entry", vector.UnsignedEntryXDR},
			failure: []string{"--entry", "not-base64"},
		},
		"doctor": {
			success: []string{"--rpc-url", doctorServer.URL},
			failure: []string{"--rpc-url", "http://127.0.0.1:0", "--timeout", "1s"},
		},
		"cross-compile": {
			success: []string{"--targets", runtime.GOOS + "/" + runtime.GOARCH, "--output-dir", t.TempDir()},
			failure: []string{"--targets", "not-a-target"},
		},
		"verify": {
			success: []string{"--entry", vector.SignedEntryXDR, "--network", "testnet"},
			failure: []string{"--entry", "not-base64", "--network", "testnet"},
		},
		"diff": {
			success: []string{"--before", vector.UnsignedEntryXDR, "--after", vector.UnsignedEntryXDR},
			failure: []string{"--before", "not-base64", "--after", vector.UnsignedEntryXDR},
		},
		"completions": {
			success: []string{"--shell", "bash"},
			failure: []string{"--shell", "unknown"},
		},
		"man": {
			success: nil,
			failure: []string{"--out", filepath.Join(t.TempDir(), "man.1")},
		},
		"wasm-budget": {
			success: []string{"--out", wasmArtifact, "--budget", "128"},
			failure: []string{"--out", wasmArtifact, "--budget", "32"},
		},
	}

	exclusions := map[string]string{
		"tui": "interactive terminal rendering and key input do not have a JSON stream",
	}
	dispatched := dispatcherCommandNames(t)
	registered := make(map[string]bool, len(commandSpecs))
	for _, spec := range commandSpecs {
		registered[spec.Name] = true
		if !dispatched[spec.Name] {
			t.Errorf("command spec %q is not dispatched by runWithStdin", spec.Name)
			continue
		}
		if reason, excluded := exclusions[spec.Name]; excluded {
			if reason == "" {
				t.Errorf("JSON exclusion for %q needs a reason", spec.Name)
			}
			if hasJSONFlag(spec) {
				t.Errorf("excluded command %q unexpectedly advertises --json", spec.Name)
			}
			continue
		}
		if !hasJSONFlag(spec) {
			t.Errorf("command %q does not advertise --json and has no explicit exclusion", spec.Name)
			continue
		}
		commandCase, ok := cases[spec.Name]
		if !ok {
			t.Errorf("command %q has no JSON success/error test case", spec.Name)
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			assertCommandJSON(t, commandCase.env, appendJSONFlag(spec.Name, commandCase.success), false)
			assertCommandJSON(t, commandCase.env, appendJSONFlag(spec.Name, commandCase.failure), true)
		})
	}
	for name := range dispatched {
		if registered[name] || name == "__complete-addresses" || name == "--version" || name == "-version" || name == "help" || name == "-h" || name == "--help" {
			continue
		}
		t.Errorf("dispatcher case %q is not a registered CLI subcommand or an explicit dispatcher-only case", name)
	}
	for name := range cases {
		if !registered[name] {
			t.Errorf("JSON case %q is not a registered CLI subcommand", name)
		}
	}
}

func appendJSONFlag(command string, args []string) []string {
	all := append([]string{command}, args...)
	return append(all, "--json")
}

func hasJSONFlag(spec commandSpec) bool {
	for _, flag := range spec.Flags {
		if flag.Name == "json" {
			return true
		}
	}
	return false
}

func assertCommandJSON(t *testing.T, env map[string]string, args []string, wantError bool) {
	t.Helper()
	stdout, stderr, err := runCLIEnv(t, env, args...)
	if wantError && err == nil {
		t.Fatalf("command unexpectedly succeeded: %v", args)
	}
	if !wantError && err != nil {
		t.Fatalf("command failed: %v: %v", args, err)
	}
	if wantError && stderr != "" {
		t.Errorf("JSON error wrote to stderr: %q", stderr)
	}
	if !validJSONOutput(stdout) {
		t.Errorf("stdout is not parseable JSON: %q", stdout)
	}
}

func validJSONOutput(output string) bool {
	output = strings.TrimSpace(output)
	if output == "" {
		return false
	}
	if json.Valid([]byte(output)) {
		return true
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if !json.Valid([]byte(strings.TrimSpace(line))) {
			return false
		}
	}
	return true
}

func dispatcherCommandNames(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}
	names := make(map[string]bool)
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Name.Name != "runWithStdin" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switchNode, ok := node.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			index, ok := switchNode.Tag.(*ast.IndexExpr)
			if !ok {
				return true
			}
			identifier, ok := index.X.(*ast.Ident)
			if !ok || identifier.Name != "args" {
				return true
			}
			zero, ok := index.Index.(*ast.BasicLit)
			if !ok || zero.Value != "0" {
				return true
			}
			for _, statement := range switchNode.Body.List {
				clause, ok := statement.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expression := range clause.List {
					literal, ok := expression.(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						continue
					}
					name, err := strconv.Unquote(literal.Value)
					if err == nil {
						names[name] = true
					}
				}
			}
			return false
		})
		break
	}
	if len(names) == 0 {
		t.Fatal("found no runWithStdin dispatcher cases; refusing an empty command audit")
	}
	return names
}
