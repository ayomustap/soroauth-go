package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSimulatePrintsEveryRecordedEntryWithItsPosition is the acceptance test for
// the subcommand's output: each entry as base64, with the operation and entry
// index it came from, and the arm reported as the host recorded it.
func TestSimulatePrintsEveryRecordedEntryWithItsPosition(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	envelope := envelopeWithEntries(t, testPayerAddress(t), "1")
	stdout, _, err := runCLI(t, "simulate", "--entry", envelope, "--rpc-url", fake.server.URL)
	if err != nil {
		t.Fatalf("simulate returned an error: %v", err)
	}

	// The fixture's record pass records a V2 entry and a legacy one, in that
	// order, so the arms prove the report came from the response.
	for _, want := range []string{
		"operation 0 entry 0: address_v2",
		"operation 0 entry 1: address",
		"min_resource_fee: 4321",
		"latest_ledger: 1234",
		"envelope: ",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output does not contain %q:\n%s", want, stdout)
		}
	}

	// Each entry's base64 must be printed too, not only its header: that is
	// what the next subcommand consumes.
	var record struct {
		Auth []string `json:"auth"`
	}
	if err := json.Unmarshal(fixtures.SimulateRecord, &record); err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	for i, entry := range record.Auth {
		if !strings.Contains(stdout, entry) {
			t.Errorf("output does not carry recorded entry %d's base64", i)
		}
	}

	if modes := fake.modes(); len(modes) != 1 || modes[0] != "record" {
		t.Errorf("auth modes %v, want exactly one record pass", modes)
	}
}

// TestSimulatePrintsTheEnvelopeToSign is what makes the subcommand part of a
// flow rather than a dead end: the envelope it prints carries the recorded
// entries, so the next step has something to sign.
func TestSimulatePrintsTheEnvelopeToSign(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	stdout, _, err := runCLI(t, "simulate",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1"),
		"--rpc-url", fake.server.URL, "--json")
	if err != nil {
		t.Fatalf("simulate --json returned an error: %v", err)
	}

	var out struct {
		Entries []struct {
			OperationIndex int    `json:"operation_index"`
			EntryIndex     int    `json:"entry_index"`
			Arm            string `json:"arm"`
			Entry          string `json:"entry"`
		} `json:"entries"`
		MinResourceFee  int64  `json:"min_resource_fee"`
		TransactionData string `json:"transaction_data"`
		LatestLedger    uint32 `json:"latest_ledger"`
		Envelope        string `json:"envelope"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout)
	}

	if len(out.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(out.Entries))
	}
	if out.Entries[0].Arm != "address_v2" || out.Entries[1].Arm != "address" {
		t.Errorf("arms %q and %q, want the arms the fixture recorded",
			out.Entries[0].Arm, out.Entries[1].Arm)
	}
	if out.Entries[0].EntryIndex != 0 || out.Entries[1].EntryIndex != 1 {
		t.Errorf("entry indices %d and %d, want 0 and 1", out.Entries[0].EntryIndex, out.Entries[1].EntryIndex)
	}
	if out.MinResourceFee != 4321 {
		t.Errorf("min_resource_fee %d, want 4321", out.MinResourceFee)
	}
	if out.LatestLedger != 1234 {
		t.Errorf("latest_ledger %d, want 1234", out.LatestLedger)
	}
	if out.TransactionData == "" {
		t.Error("transaction_data is empty, so the resources and fee were dropped")
	}
	if out.Envelope == "" {
		t.Fatal("no envelope was printed, so the next step has nothing to sign")
	}

	// The printed envelope must be the input one with the recorded entries on
	// the operation, which is what makes it signable.
	printed := decodeEnvelope(t, out.Envelope)
	ops := printed.Operations()
	if len(ops) != 1 {
		t.Fatalf("the printed envelope carries %d operations, want 1", len(ops))
	}
	invoke, ok := ops[0].Body.GetInvokeHostFunctionOp()
	if !ok {
		t.Fatal("the printed envelope's operation is not an invokeHostFunction")
	}
	if len(invoke.Auth) != 2 {
		t.Errorf("the printed envelope carries %d authorization entries, want 2", len(invoke.Auth))
	}
}

// TestSimulateReportsTheArmTheHostRecordedNotTheOneAskedFor covers the case the
// acceptance criteria single out: --use-upgraded-auth is best-effort, so a host
// that recorded the legacy arm must be reported that way.
func TestSimulateReportsTheArmTheHostRecordedNotTheOneAskedFor(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	// The record fixture's second entry is legacy. A host that could not emit
	// V2 answers this way whatever was requested.
	fake := newFakeRPC(t, fixtures)

	stdout, _, err := runCLI(t, "simulate",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1"),
		"--rpc-url", fake.server.URL, "--use-upgraded-auth")
	if err != nil {
		t.Fatalf("simulate returned an error: %v", err)
	}
	if upgraded := fake.upgraded(); len(upgraded) != 1 || !upgraded[0] {
		t.Errorf("useUpgradedAuth was %v on the request, want [true]", upgraded)
	}
	if !strings.Contains(stdout, "entry 1: address") {
		t.Errorf("the legacy entry the host recorded was not reported as legacy:\n%s", stdout)
	}
}

// TestSimulateReportsTheHostErrorAndExitsNonZero: a refused simulation is
// reported with the host's own message, not a reshaped one.
func TestSimulateReportsTheHostErrorAndExitsNonZero(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)
	const hostError = "HostError: Error(WasmVm, InvalidAction)"
	fake.failSimulate = hostError

	stdout, _, err := runCLI(t, "simulate",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1"),
		"--rpc-url", fake.server.URL)
	if err == nil {
		t.Fatalf("a refused simulation succeeded, printing %q", stdout)
	}
	if !strings.Contains(err.Error(), hostError) {
		t.Errorf("error %q does not carry the host's message", err)
	}
	if code := ExitCode(err); code != ExitGeneralError {
		t.Errorf("exit code %d, want %d", code, ExitGeneralError)
	}
	if stdout != "" {
		t.Errorf("a failing command wrote to stdout: %q", stdout)
	}
}

// TestSimulateJSONErrorStaysOnStdout pins the CLI's --json contract: one JSON
// object on stdout, nothing on stderr, non-zero exit.
func TestSimulateJSONErrorStaysOnStdout(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)
	fake.failSimulate = "HostError: something"

	stdout, stderr, err := runCLI(t, "simulate",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1"),
		"--rpc-url", fake.server.URL, "--json")
	if err == nil {
		t.Fatal("a refused simulation succeeded")
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got %q", stderr)
	}
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not a JSON error object: %v\noutput: %s", err, stdout)
	}
	if out.Error == "" {
		t.Error("the JSON error object carries an empty error field")
	}
}

// TestSimulateRejects covers the usage errors: everything the caller can get
// wrong about the flags is a usage error that never reaches the network.
func TestSimulateRejects(t *testing.T) {
	envelope := envelopeWithEntries(t, testPayerAddress(t), "1")

	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantMsg string
	}{
		{
			name:    "no entry",
			args:    []string{"simulate"},
			wantMsg: "--entry is required",
		},
		{
			name:    "no endpoint",
			args:    []string{"simulate", "--entry", envelope},
			wantMsg: "SOROAUTH_RPC_URL",
		},
		{
			name:    "not base64",
			args:    []string{"simulate", "--entry", "not-base64", "--rpc-url", "http://rpc.invalid"},
			wantMsg: "not valid base64",
		},
		{
			name:    "an authorization entry rather than an envelope",
			args:    []string{"simulate", "--entry", loadVector(t, "v2_single_testnet").UnsignedEntryXDR, "--rpc-url", "http://rpc.invalid"},
			wantMsg: "decoding --entry as a transaction envelope",
		},
		{
			name:    "unknown flag",
			args:    []string{"simulate", "--nope"},
			wantMsg: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLIEnv(t, tt.env, tt.args...)
			if err == nil {
				t.Fatalf("the command succeeded, printing %q", stdout)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if code := ExitCode(err); code != ExitUsageError {
				t.Errorf("exit code %d, want %d", code, ExitUsageError)
			}
			if stdout != "" {
				t.Errorf("a failing command wrote to stdout: %q", stdout)
			}
		})
	}
}

// TestSimulateUsesSOROAUTH_RPC_URL proves the environment fallback works, since
// a shell that exports it never passes --rpc-url.
func TestSimulateUsesSOROAUTH_RPC_URL(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	stdout, _, err := runCLIEnv(t,
		map[string]string{"SOROAUTH_RPC_URL": fake.server.URL},
		"simulate", "--entry", envelopeWithEntries(t, testPayerAddress(t), "1"))
	if err != nil {
		t.Fatalf("simulate with SOROAUTH_RPC_URL returned an error: %v", err)
	}
	if !strings.Contains(stdout, "operation 0 entry 0") {
		t.Errorf("output does not report a recorded entry:\n%s", stdout)
	}
}

// TestSimulateRefusesAnInvocationThatNeedsNoAuthorization covers the fail-closed
// reading: nothing recorded is an error, not an empty success.
func TestSimulateRefusesAnInvocationThatNeedsNoAuthorization(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fixtures.SimulateRecord = json.RawMessage(`{"transactionData":"","minResourceFee":"0","latestLedger":1,"results":[{"auth":null}]}`)
	fake := newFakeRPC(t, fixtures)

	stdout, _, err := runCLI(t, "simulate",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1"),
		"--rpc-url", fake.server.URL)
	if err == nil {
		t.Fatalf("a simulation that recorded no entries succeeded, printing %q", stdout)
	}
	if code := ExitCode(err); code != ExitUsageError {
		t.Errorf("exit code %d, want %d (a simulation with nothing to authorize cannot be retried)", code, ExitUsageError)
	}
}
