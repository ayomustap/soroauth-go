package soroauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/soroauth/soroauth-go/internal/decodepolicy"
)

// TestExportedFunctionsDecodeThroughTheBound rather than through the Go SDK's
// defaults.
//
// decode.go exists because the SDK's default limits are much looser than this
// library wants for untrusted input, and a bound only helps where it is used.
// Nothing in the compiler stops the next exported function from calling
// xdr.SafeUnmarshalBase64 directly, which is how the hardening quietly stops
// covering the newest code: the decoder still works and the tests still pass,
// and the bound is simply missing where it was most recently needed.
//
// The scanner is internal/decodepolicy, and its own tests prove it reports a
// violation on a fixture that has one and stays silent on one that does not.
// This test is the enforcement: it runs the scanner over this repository and
// fails naming the exported function, the call chain that reaches the decoder
// and the file and line of the call.
//
// A deliberate exception is a `decode-allow:` comment in the function's doc
// comment with a reason, which also makes the exception visible in review
// rather than buried in this test.
func TestExportedFunctionsDecodeThroughTheBound(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locating the module root: %v", err)
	}

	result, err := decodepolicy.Root(root)
	if err != nil {
		t.Fatalf("decodepolicy.Root: %v", err)
	}

	// A scanner that matched no exported function at all is indistinguishable
	// from a clean tree, and would pass this test forever while enforcing
	// nothing. Fail loudly instead.
	if result.EntryPoints == 0 {
		t.Fatalf("the decoder-policy scan found no exported functions under %s; "+
			"a scanner that matches nothing must not pass", root)
	}
	if result.Packages == 0 {
		t.Fatalf("the decoder-policy scan visited no packages under %s", root)
	}

	for _, violation := range result.Violations {
		t.Errorf("%s", violation)
	}

	t.Logf("examined %d exported functions across %d packages, %d deliberate exceptions",
		result.EntryPoints, result.Packages, len(result.Allowances))
	for _, allowance := range result.Allowances {
		t.Logf("allowed: %s", allowance)
	}
}

// repoRoot walks up from the package directory to the directory holding
// go.mod, since tests run with their package directory as the working
// directory rather than the module root.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
