package soroauth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type fuzzTargetDefinition struct {
	name       string
	packageDir string
	inputCount int
}

func TestEveryFuzzTargetHasValidCorpus(t *testing.T) {
	targets := discoverFuzzTargets(t)
	if len(targets) == 0 {
		t.Fatal("found no Go fuzz targets; refusing a vacuous corpus check")
	}

	doc, err := os.ReadFile(filepath.Join("docs", "fuzzing.md"))
	if err != nil {
		t.Fatalf("reading docs/fuzzing.md: %v", err)
	}
	documented := make(map[string]bool)
	for _, name := range regexp.MustCompile(`Fuzz[A-Za-z0-9_]+`).FindAllString(string(doc), -1) {
		documented[name] = true
	}

	discovered := make(map[string]bool, len(targets))
	for _, target := range targets {
		discovered[target.name] = true
		if !documented[target.name] {
			t.Errorf("fuzz target %s is missing from docs/fuzzing.md", target.name)
		}
		seedDir := filepath.Join(target.packageDir, "testdata", "fuzz", target.name)
		entries, err := os.ReadDir(seedDir)
		if err != nil {
			t.Errorf("fuzz target %s has no corpus directory %s: %v", target.name, seedDir, err)
			continue
		}
		if len(entries) == 0 {
			t.Errorf("fuzz target %s has an empty corpus directory %s", target.name, seedDir)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				t.Errorf("fuzz target %s corpus contains unexpected directory %s", target.name, entry.Name())
				continue
			}
			path := filepath.Join(seedDir, entry.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("reading seed %s: %v", path, err)
				continue
			}
			if err := validateFuzzCorpus(raw, target.inputCount); err != nil {
				t.Errorf("seed %s is not a valid Go fuzz corpus file: %v", path, err)
			}
		}
	}
	for name := range documented {
		if strings.HasPrefix(name, "Fuzz") && !discovered[name] {
			t.Errorf("docs/fuzzing.md lists %s, but no Go fuzz target declares it", name)
		}
	}
}

func discoverFuzzTargets(t *testing.T) []fuzzTargetDefinition {
	t.Helper()

	var targets []fuzzTargetDefinition
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "target", "dist", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(function.Name.Name, "Fuzz") || function.Type.Params == nil || len(function.Type.Params.List) != 1 {
				continue
			}
			if !isTestingF(function.Type.Params.List[0].Type) {
				continue
			}
			inputCount, ok := fuzzInputCount(function.Body)
			if !ok {
				return fmt.Errorf("fuzz target %s has no single-argument F.Fuzz callback", function.Name.Name)
			}
			targets = append(targets, fuzzTargetDefinition{
				name:       function.Name.Name,
				packageDir: filepath.Dir(path),
				inputCount: inputCount,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("discovering fuzz targets: %v", err)
	}
	return targets
}

func isTestingF(expression ast.Expr) bool {
	pointer, ok := expression.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "F" {
		return false
	}
	packageName, ok := selector.X.(*ast.Ident)
	return ok && packageName.Name == "testing"
}

func fuzzInputCount(body *ast.BlockStmt) (int, bool) {
	if body == nil {
		return 0, false
	}
	var count int
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || found {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Fuzz" || len(call.Args) != 1 {
			return true
		}
		function, ok := call.Args[0].(*ast.FuncLit)
		if !ok || function.Type.Params == nil {
			return true
		}
		for i, parameter := range function.Type.Params.List {
			if i == 0 {
				continue
			}
			if len(parameter.Names) == 0 {
				count++
			} else {
				count += len(parameter.Names)
			}
		}
		found = true
		return true
	})
	return count, found && count > 0
}

func validateFuzzCorpus(raw []byte, wantArguments int) error {
	if len(raw) == 0 {
		return os.ErrInvalid
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) < 2 || lines[0] != "go test fuzz v1" {
		return fmt.Errorf("missing Go fuzz corpus header")
	}
	if len(lines)-1 != wantArguments {
		return fmt.Errorf("has %d arguments, want %d", len(lines)-1, wantArguments)
	}
	for _, line := range lines[1:] {
		expression, err := parser.ParseExpr(line)
		if err != nil {
			return err
		}
		call, ok := expression.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return fmt.Errorf("argument is not a []byte conversion")
		}
		array, ok := call.Fun.(*ast.ArrayType)
		if !ok {
			return fmt.Errorf("argument is not a []byte conversion")
		}
		element, ok := array.Elt.(*ast.Ident)
		if !ok || element.Name != "byte" {
			return fmt.Errorf("argument is not a []byte conversion")
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return fmt.Errorf("[]byte argument is not a string literal")
		}
		if _, err := strconv.Unquote(literal.Value); err != nil {
			return err
		}
	}
	return nil
}
