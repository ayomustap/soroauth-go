// Package decodepolicy turns one prose rule into a check that bites: no
// exported function of this module may reach the Go SDK's unbounded XDR
// decoders.
//
// # Why the rule exists
//
// decode.go bound the untrusted input this library accepts, but a bound only
// applies where it is used. Nothing stopped the next exported function from
// calling xdr.SafeUnmarshalBase64 directly, and that is exactly how a
// hardening measure quietly stops covering the newest code: the decoder keeps
// working, the tests keep passing, and the bound is simply absent where it was
// most recently needed. A review note does not survive that; a check does.
//
// # What it looks for
//
// The SDK's xdr.SafeUnmarshalBase64 sets go-xdr's MaxInputLen from the input
// it is handed, so it can never refuse an input for being too long, and its
// default maximum depth is 1500 (go-xdr/xdr3 DecodeDefaultMaxDepth) — far
// looser than this library's deliberate limits. Decoding untrusted bytes
// through it is the defect this package reports.
//
// xdr.SafeUnmarshalBase64WithOptions is deliberately NOT reported: it takes
// explicit DecodeOptions, so a caller passing a bound has done the right
// thing, and that is the call DecodeAuthorizationEntry makes.
//
// # What "reaching" means
//
// A function reaches a decoder when the call is in its own body — including
// inside a nested function literal — or inside any function of the same
// package it calls, transitively. Package-local calls only: a call through an
// interface, a function value or another package is not followed, because this
// package reads syntax, not types, and guessing there would produce reports a
// reader cannot check. The report names the whole call chain for that reason.
//
// # Deliberate exceptions
//
// A function whose body contains an unbounded decode on purpose carries an
// explicit allowance comment in its doc comment:
//
//	// decode-allow: the bytes are the response to the request this function
//	// just made, not a caller-supplied blob.
//
// The traversal does not descend into an allowed function, so its callers are
// not reported either. The exception is therefore a property of one named
// function, visible in the source and in review, rather than a list inside
// this package that could drift away from the code it describes.
package decodepolicy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// AllowanceComment is the marker that annotates a deliberate exception. It
// appears in the doc comment of the function that makes the unbounded call.
const AllowanceComment = "decode-allow:"

// xdrImportPath is the package whose decoders this rule is about. The local
// name a file gives it is resolved from that file's import block, so the match
// is on the decoder and not on a name: encoding/json's Unmarshal and
// encoding/asn1's Unmarshal are not XDR decoders, and a rule that flagged them
// would be a rule nobody could keep green.
const xdrImportPath = "github.com/stellar/go-stellar-sdk/xdr"

// unboundedDecoders are the SDK's unbounded decode entry points, called on the
// xdr package's local name.
//
// SafeUnmarshalBase64WithOptions is absent on purpose: it applies the options
// it is given, which is how a caller bounds the decode, and it is what
// DecodeAuthorizationEntry calls. Unmarshal and SafeUnmarshal are the
// byte-slice equivalents of the base64 one and carry the same go-xdr defaults
// (MaxInputLen set from the input, a default maximum depth of 1500).
var unboundedDecoders = map[string]bool{
	"SafeUnmarshalBase64": true,
	"SafeUnmarshal":       true,
	"Unmarshal":           true,
}

// Violation is one exported function that reaches an unbounded decoder.
type Violation struct {
	// Package is the package's directory relative to the module root, "." for
	// the root package.
	Package string
	// Function is the exported function or method that reaches the decoder.
	// A method is reported as "Receiver.Method".
	Function string
	// Chain is the call path from Function to the decode, Function first and
	// the decoder call last, so a reader can see how the bound is bypassed.
	Chain []string
	// Call is the decoder call as written, for example
	// "xdr.SafeUnmarshalBase64".
	Call string
	// Position is the file and line the decoder call is at.
	Position string
}

// String renders a violation as one multi-line report.
func (v Violation) String() string {
	return fmt.Sprintf("%s: exported %s reaches %s through %s (at %s); decode through the "+
		"library's bounded decoder instead, or annotate the function with a %q comment and a reason",
		v.Package, v.Function, v.Call, strings.Join(v.Chain, " -> "), v.Position, AllowanceComment)
}

// Result is what a walk of the module found.
type Result struct {
	// Violations is one entry per exported function that reaches an unbounded
	// decoder without an allowance.
	Violations []Violation
	// EntryPoints is the number of exported functions and methods the walk
	// examined. A caller must refuse to treat a zero here as a pass: a scanner
	// that matched nothing at all is indistinguishable from a clean tree.
	EntryPoints int
	// Packages is the number of packages the walk visited.
	Packages int
	// Allowances names every function annotated as a deliberate exception, so
	// the set is reviewable as one list without grepping the tree.
	Allowances []string
}

// skipDirNames are directories the walk never descends into: no first-party
// Go source, fixtures that are not part of this module, or a nested module
// whose public surface is checked by its own CI job.
var skipDirNames = map[string]bool{
	".git":         true,
	"node_modules": true,
	"testdata":     true,
	"adapters":     true,
	".github":      true,
	"e2e":          true,
	"docs":         true,
}

// Root walks every first-party package under dir and reports every exported
// function or method that reaches one of the SDK's unbounded decoders.
func Root(dir string) (Result, error) {
	var result Result

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if path != dir && (skipDirNames[base] || strings.HasPrefix(base, ".")) {
			return filepath.SkipDir
		}
		if path != dir {
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
		}

		found, scanned, allow, walkErr := checkDir(path, dir)
		if walkErr != nil {
			return walkErr
		}
		if scanned {
			result.Packages++
			result.EntryPoints += found.entryPoints
			result.Violations = append(result.Violations, found.violations...)
			result.Allowances = append(result.Allowances, allow...)
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("decodepolicy: walking %s: %w", dir, err)
	}

	sort.Slice(result.Violations, func(i, j int) bool {
		if result.Violations[i].Package != result.Violations[j].Package {
			return result.Violations[i].Package < result.Violations[j].Package
		}
		return result.Violations[i].Function < result.Violations[j].Function
	})
	sort.Strings(result.Allowances)
	return result, nil
}

// scanResult is one directory's contribution to the walk.
type scanResult struct {
	violations  []Violation
	entryPoints int
}

// checkDir inspects the non-test .go files directly in dir. The second return
// value reports whether the directory held any Go source at all, so a
// directory of fixtures is not counted as a scanned package.
func checkDir(dir, root string) (scanResult, bool, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return scanResult{}, false, nil, fmt.Errorf("decodepolicy: reading %s: %w", dir, err)
	}

	rel, err := filepath.Rel(root, dir)
	if err != nil {
		rel = dir
	}

	fset := token.NewFileSet()
	functions := map[string]*function{}
	var order []string

	sources := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			return scanResult{}, false, nil, fmt.Errorf("decodepolicy: parsing %s: %w", path, parseErr)
		}
		sources++
		collect(fset, file, xdrLocalNames(file), functions, &order)
	}

	if sources == 0 {
		return scanResult{}, false, nil, nil
	}

	reaches, paths := reachability(functions)

	result := scanResult{}
	var allowances []string
	for _, name := range order {
		fn := functions[name]
		if fn.allowance != "" {
			allowances = append(allowances, fmt.Sprintf("%s/%s: %s", rel, name, fn.allowance))
		}
		if !fn.exported {
			continue
		}
		result.entryPoints++

		found, chain, call := reaches(name)
		if !found {
			continue
		}
		site := paths[name]
		result.violations = append(result.violations, Violation{
			Package:  rel,
			Function: name,
			Chain:    chain,
			Call:     call,
			Position: site,
		})
	}

	return result, true, allowances, nil
}

// callSite is one call written in a function body.
type callSite struct {
	// text is the call as written, for example "xdr.SafeUnmarshalBase64".
	text string
	// name is the callee's bare name: the selector's field for a qualified or
	// method call, the identifier for a plain one.
	name string
	// decoder is true when the callee is one of the SDK's unbounded decoders.
	decoder bool
	// position is the file and line.
	position string
	// local is true when the callee names another function in this package,
	// so the traversal should follow it.
	local bool
}

// function is one function declaration, top-level only. A nested function
// literal is not a node of its own: its calls belong to the function that
// contains it, because that is the unit this rule is about — the exported
// function a caller can reach.
type function struct {
	name      string
	exported  bool
	allowance string
	calls     []callSite
}

// xdrLocalNames returns the names file refers to the xdr package by: the
// default name, an explicit alias, or both when a file aliases it. A file that
// does not import it returns an empty set, which makes every decoder call in it
// invisible to this rule.
func xdrLocalNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != xdrImportPath {
			continue
		}
		if spec.Name == nil {
			names["xdr"] = true
			continue
		}
		switch spec.Name.Name {
		case "_", ".":
			// A blank import cannot name a decoder, and this rule does not
			// follow a dot import: an unqualified Unmarshal is far more likely
			// to be another package's than to be xdr's, and reporting it would
			// be a false positive a reader cannot check.
		default:
			names[spec.Name.Name] = true
		}
	}
	return names
}

// collect records every top-level function and method declared in file.
func collect(fset *token.FileSet, file *ast.File, xdrNames map[string]bool, functions map[string]*function, order *[]string) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		name := fn.Name.Name
		if fn.Recv != nil {
			name = receiverName(fn.Recv) + "." + fn.Name.Name
		}

		info := &function{
			name:      name,
			exported:  exportedDecl(fn),
			allowance: allowanceIn(fn.Doc),
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			site, ok := callOf(fset, call, xdrNames)
			if !ok {
				return true
			}
			info.calls = append(info.calls, site)
			return true
		})

		if _, exists := functions[name]; !exists {
			*order = append(*order, name)
		}
		functions[name] = info
	}
}

// callOf turns a call expression into a callSite, or reports false for a call
// it cannot name (a call through a function value, for instance).
func callOf(fset *token.FileSet, call *ast.CallExpr, xdrNames map[string]bool) (callSite, bool) {
	pos := fset.Position(call.Lparen).String()
	switch callee := call.Fun.(type) {
	case *ast.Ident:
		return callSite{text: callee.Name, name: callee.Name, position: pos}, true
	case *ast.SelectorExpr:
		qualifier, isIdent := callee.X.(*ast.Ident)
		text := callee.Sel.Name
		if isIdent {
			text = qualifier.Name + "." + callee.Sel.Name
		}
		return callSite{
			text:     text,
			name:     callee.Sel.Name,
			decoder:  isIdent && xdrNames[qualifier.Name] && unboundedDecoders[callee.Sel.Name],
			position: pos,
		}, true
	}
	return callSite{}, false
}

// reachability marks which package-local calls name another function in this
// package, then answers, per function, whether the unbounded decoder is
// reachable and through which chain.
//
// An allowed function is a leaf: the traversal does not descend into it, so
// the exception is confined to the function that carries it and its callers
// are not reported for a decision it made and documented.
func reachability(functions map[string]*function) (func(string) (bool, []string, string), map[string]string) {
	for _, fn := range functions {
		for i := range fn.calls {
			if fn.calls[i].decoder {
				continue
			}
			if _, ok := functions[fn.calls[i].name]; ok {
				fn.calls[i].local = true
			}
		}
	}

	type outcome struct {
		found bool
		chain []string
		call  string
		site  string
	}
	memo := map[string]outcome{}
	visiting := map[string]bool{}

	var resolve func(name string) outcome
	resolve = func(name string) outcome {
		if got, ok := memo[name]; ok {
			return got
		}
		fn, ok := functions[name]
		if !ok {
			return outcome{}
		}
		// A recursive package would otherwise recurse forever; the calls in
		// the cycle are already visited by the time it is re-entered.
		if visiting[name] {
			return outcome{}
		}
		visiting[name] = true
		defer delete(visiting, name)

		var found outcome
		if fn.allowance == "" {
			for _, call := range fn.calls {
				if call.decoder {
					found = outcome{found: true, chain: []string{name}, call: call.text, site: call.position}
					break
				}
			}
		}
		if !found.found {
			for _, call := range fn.calls {
				if !call.local {
					continue
				}
				next := resolve(call.name)
				if !next.found {
					continue
				}
				found = outcome{
					found: true,
					chain: append([]string{name}, next.chain...),
					call:  next.call,
					site:  next.site,
				}
				break
			}
		}
		if fn.allowance != "" {
			found = outcome{}
		}
		memo[name] = found
		return found
	}

	sites := map[string]string{}
	return func(name string) (bool, []string, string) {
		got := resolve(name)
		if !got.found {
			return false, nil, ""
		}
		sites[name] = got.site
		return true, got.chain, got.call
	}, sites
}

// exportedDecl reports whether a declaration is part of the package's public
// surface: an exported name, and for a method an exported receiver type, since
// a method on an unexported type cannot be reached from outside the package.
func exportedDecl(fn *ast.FuncDecl) bool {
	if !fn.Name.IsExported() {
		return false
	}
	if fn.Recv == nil {
		return true
	}
	return ast.IsExported(receiverName(fn.Recv))
}

// allowanceIn returns the reason carried by an allowance comment, or "".
//
// The reason is read from the marker line and the comment lines that continue
// it, up to the first blank comment line. A one-line reason is easy to write
// and easy to be useless, and an allowance whose justification is lost to the
// end of its first line is a worse record than no allowance at all.
func allowanceIn(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	lines := make([]string, 0, len(doc.List))
	for _, comment := range doc.List {
		text := comment.Text
		if strings.HasPrefix(text, "//") {
			lines = append(lines, strings.TrimPrefix(text, "//"))
			continue
		}
		// A block comment is one comment; its lines are separated by newlines
		// and its decoration is dropped.
		text = strings.TrimSuffix(strings.TrimPrefix(text, "/*"), "*/")
		for _, line := range strings.Split(text, "\n") {
			lines = append(lines, strings.TrimPrefix(strings.TrimSpace(line), "*"))
		}
	}

	start := -1
	for i, line := range lines {
		if strings.Contains(line, AllowanceComment) {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}

	var reason []string
	for i := start; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if i > start && line == "" {
			break
		}
		if i == start {
			idx := strings.Index(line, AllowanceComment)
			line = line[idx+len(AllowanceComment):]
		}
		reason = append(reason, line)
	}
	return strings.TrimSpace(strings.Join(reason, " "))
}

// receiverName extracts the receiver's bare type name.
func receiverName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.IndexListExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}
