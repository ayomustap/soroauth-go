package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
)

// TestGoVersionParsing covers the pure parsing and comparison logic without
// touching exec.Command, so it does not depend on which Go happens to be on
// the test machine's PATH.
func TestGoVersionParsing(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
		wantOK bool
	}{
		{name: "typical", output: "go version go1.25.4 linux/amd64\n", want: "go1.25.4", wantOK: true},
		{name: "two-component", output: "go version go1.25 darwin/arm64\n", want: "go1.25", wantOK: true},
		{name: "garbage", output: "not a go version string", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseGoVersion(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("parseGoVersion(%q) ok = %v, want %v", tt.output, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("parseGoVersion(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestGoVersionAtLeast(t *testing.T) {
	tests := []struct {
		version, floor string
		want           bool
	}{
		{"go1.25.4", "go1.25.0", true},
		{"go1.25.0", "go1.25.0", true},
		{"go1.24.9", "go1.25.0", false},
		{"go1.9.0", "go1.10.0", false}, // numeric compare, not lexical
		{"go1.10.0", "go1.9.0", true},
		{"go2.0.0", "go1.25.0", true},
		{"go1.25", "go1.25.0", true},
	}
	for _, tt := range tests {
		if got := goVersionAtLeast(tt.version, tt.floor); got != tt.want {
			t.Errorf("goVersionAtLeast(%q, %q) = %v, want %v", tt.version, tt.floor, got, tt.want)
		}
	}
}

// TestDoctorGoToolchainCheck exercises the real exec.LookPath/exec.Command
// path against whatever Go is actually running this test, which CI and every
// contributor's machine satisfy the module's own floor for.
func TestDoctorGoToolchainCheck(t *testing.T) {
	check := checkGoToolchain()
	if !check.Pass {
		t.Errorf("the go toolchain running this test failed its own floor check: %+v", check)
	}
}

// TestDoctorNetworkCheck uses a local httptest server for the reachable case
// (never the real network, per this repo's unit-test rule) and a closed port
// for the unreachable case.
func TestDoctorNetworkCheck(t *testing.T) {
	t.Run("reachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		check := checkNetwork(srv.URL, time.Second)
		if !check.Pass {
			t.Errorf("a running local server was reported unreachable: %+v", check)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		// Port 0 never accepts connections; this fails fast rather than
		// waiting out a real timeout.
		check := checkNetwork("http://127.0.0.1:0", time.Second)
		if check.Pass {
			t.Error("a request to a closed port was reported reachable")
		}
		if check.Detail == "" {
			t.Error("an unreachable check has no detail explaining why")
		}
	})
}

func TestDoctorSecretEnvCheck(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		check := checkSecretEnv("SEED", func(k string) string {
			if k == "SEED" {
				return "SABCDEXAMPLE"
			}
			return ""
		})
		if !check.Pass {
			t.Errorf("a set variable was reported unset: %+v", check)
		}
		if strings.Contains(check.Detail, "SABCDEXAMPLE") {
			t.Errorf("the check detail leaked the secret's value: %q", check.Detail)
		}
	})

	t.Run("unset", func(t *testing.T) {
		check := checkSecretEnv("SEED", func(string) string { return "" })
		if check.Pass {
			t.Error("an unset variable was reported set")
		}
	})
}

// TestDoctorCLIAllPass drives the full subcommand against a local server and
// a set secret variable, asserting exit code, JSON shape, and that nothing
// beyond the report is written to either stream.
func TestDoctorCLIAllPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	seed := doctorTestKey(t, "soroauth-doctor-allpass").Seed()
	stdout, stderr, err := runCLIEnv(t, map[string]string{"SEED": seed},
		"doctor", "--rpc-url", srv.URL, "--secret-env", "SEED", "--json")
	if err != nil {
		t.Fatalf("doctor returned an unexpected error: %v", err)
	}
	if ExitCode(err) != ExitOK {
		t.Errorf("exit code %d, want %d", ExitCode(err), ExitOK)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty, got: %q", stderr)
	}

	var report doctorReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}
	if !report.OK {
		t.Errorf("report.OK is false: %+v", report)
	}
	if len(report.Checks) != 4 {
		t.Fatalf("got %d checks, want 4 (go toolchain, network, secret env, signer possession)", len(report.Checks))
	}
	for _, c := range report.Checks {
		if !c.Pass {
			t.Errorf("check %q failed: %+v", c.Name, c)
		}
	}
	if strings.Contains(stdout, seed) {
		t.Errorf("stdout leaked the secret: %q", stdout)
	}
}

func doctorTestKey(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// TestDoctorSignerPossession proves doctor runs the possession check when a
// signer is configured, and that a seed configured for the wrong account is
// caught: the failure a service would otherwise discover only after fees.
func TestDoctorSignerPossession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	key := doctorTestKey(t, "soroauth-doctor-possession")
	other := doctorTestKey(t, "soroauth-doctor-other")
	env := map[string]string{"SEED": key.Seed(), "BAD": "SABCDEXAMPLE"}

	possession := func(t *testing.T, args ...string) (doctorCheck, doctorReport) {
		t.Helper()
		full := append([]string{"doctor", "--rpc-url", srv.URL, "--json"}, args...)
		stdout, _, _ := runCLIEnv(t, env, full...)
		var report doctorReport
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("stdout is not valid JSON: %v: %q", err, stdout)
		}
		for _, c := range report.Checks {
			if c.Name == "signer possession" {
				return c, report
			}
		}
		return doctorCheck{}, report
	}

	t.Run("the seed controls its own address", func(t *testing.T) {
		c, report := possession(t, "--secret-env", "SEED")
		if !c.Pass || !report.OK || !strings.Contains(c.Detail, key.Address()) {
			t.Fatalf("check = %+v, ok = %v", c, report.OK)
		}
	})
	t.Run("the seed is configured for the wrong account", func(t *testing.T) {
		c, report := possession(t, "--secret-env", "SEED", "--address", other.Address())
		if c.Pass || report.OK || !strings.Contains(c.Detail, "does not match its configured address") {
			t.Fatalf("check = %+v, ok = %v", c, report.OK)
		}
	})
	t.Run("a value that is not a seed", func(t *testing.T) {
		c, report := possession(t, "--secret-env", "BAD")
		if c.Pass || report.OK || strings.Contains(c.Detail, "SABCDEXAMPLE") {
			t.Fatalf("check = %+v, ok = %v", c, report.OK)
		}
	})
	t.Run("no signer configured means no possession check", func(t *testing.T) {
		c, _ := possession(t)
		if c.Name != "" {
			t.Fatalf("possession check ran without a signer: %+v", c)
		}
	})
}

// TestDoctorCLIFailure asserts the failure exit code and that a failing
// network check still produces a clean, results-only report — never a
// secret, and (per this repo's JSON convention) nothing extra on stderr.
func TestDoctorCLIFailure(t *testing.T) {
	stdout, stderr, err := runCLIEnv(t, map[string]string{"SEED": "SABCDEXAMPLE"},
		"doctor", "--rpc-url", "http://127.0.0.1:0", "--secret-env", "MISSING_VAR", "--json")
	if err == nil {
		t.Fatal("doctor succeeded despite an unreachable URL and a missing variable")
	}
	if ExitCode(err) != ExitGeneralError {
		t.Errorf("exit code %d, want %d (ExitGeneralError)", ExitCode(err), ExitGeneralError)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got: %q", stderr)
	}

	var report doctorReport
	if jsonErr := json.Unmarshal([]byte(stdout), &report); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", jsonErr, stdout)
	}
	if report.OK {
		t.Error("report.OK is true despite failing checks")
	}
	var sawNetworkFail, sawSecretFail bool
	for _, c := range report.Checks {
		if c.Name == "network" && !c.Pass {
			sawNetworkFail = true
		}
		if c.Name == "secret env: MISSING_VAR" && !c.Pass {
			sawSecretFail = true
		}
	}
	if !sawNetworkFail {
		t.Error("the network check did not fail for an unreachable URL")
	}
	if !sawSecretFail {
		t.Error("the secret env check did not fail for a missing variable")
	}
	if strings.Contains(stdout, "SABCDEXAMPLE") {
		t.Errorf("stdout leaked the secret: %q", stdout)
	}
}

// TestDoctorHumanReadable covers the non-JSON output path.
func TestDoctorHumanReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stdout, _, err := runCLI(t, "doctor", "--rpc-url", srv.URL)
	if err != nil {
		t.Fatalf("doctor returned an unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "PASS") {
		t.Errorf("human-readable output has no PASS marker: %q", stdout)
	}
	if !strings.Contains(stdout, "all checks passed") {
		t.Errorf("human-readable output missing the summary line: %q", stdout)
	}
}

// TestDoctorNoSecretEnvFlagSkipsThatCheck confirms the secret check is only
// run when --secret-env is given, since it has nothing to check otherwise.
func TestDoctorNoSecretEnvFlagSkipsThatCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stdout, _, err := runCLI(t, "doctor", "--rpc-url", srv.URL, "--json")
	if err != nil {
		t.Fatalf("doctor returned an unexpected error: %v", err)
	}
	var report doctorReport
	if jsonErr := json.Unmarshal([]byte(stdout), &report); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v", jsonErr)
	}
	if len(report.Checks) != 2 {
		t.Errorf("got %d checks with no --secret-env, want 2 (go toolchain, network)", len(report.Checks))
	}
	for _, c := range report.Checks {
		if strings.HasPrefix(c.Name, "secret env") {
			t.Error("a secret env check ran despite no --secret-env flag")
		}
	}
}
