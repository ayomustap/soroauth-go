package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const verifyUsage = `soroauth verify — check an entry's signatures without submitting it.

usage:
  soroauth verify --entry <base64> --network <name|passphrase> [--valid-until <ledger>] [--allow-unsigned] [--json]
  soroauth verify --entries <file|-> --network <name|passphrase> [--valid-until <ledger>] [--allow-unsigned] [--json]

Verification answers one question: do the signatures already on this entry
verify over the payload the entry itself commits to? The payload is rebuilt
from the entry — its credentials arm, nonce, address, invocation tree and the
SignatureExpirationLedger stored on it — so an entry that was tampered with
after signing, or signed over a different expiration than it carries, is caught
here instead of on-chain after fees are paid.

Only classic account signatures can be decided offline: the built-in vector
holding one {public_key, signature} map, checked against the 32-byte payload.
Every other shape — a custom account's signature, a node addressed to a C…
contract — is reported as "cannot_check", never as "verified", because only
the account's own __check_auth defines what it accepts. Whether the key that
signed is actually a signer of the account, and whether enough signers signed
to meet its threshold, are account-state questions this command cannot see and
does not claim to answer.

Each credential node is reported: verified, unsigned, invalid (a well-formed
signature that does not verify), or cannot_check. Under CAP-71-01 a delegates
entry may legitimately leave its top-level node Void, so an unsigned node is
reported rather than treated as a failure; pass --allow-unsigned to accept it.

The exit code is 4 when any node is invalid or cannot_check, when any node is
unsigned and --allow-unsigned was not given, or when --valid-until disagrees
with the expiration the entry carries. It is 0 only when every node verified.

--entry accepts either an authorization entry or a whole transaction envelope;
an envelope is verified entry by entry, each with the operation and entry index
it came from. A fee-bump envelope is read through to its inner transaction.

--entries verifies many entries: one base64 authorization entry per line from
the named file ("-" for stdin), blank lines skipped. An envelope is not a batch
line; select its entries first. Each input is reported with its 1-based
position: an "entry N:" header and the same report as a single entry without
--json, or one array element per input with it —
{"entry": N, "result": {...}} on success, {"entry": N, "error": "..."} on
failure. A line that fails to decode or verify does not stop the run; the exit
code is the first failure's.

--valid-until, when given, is an assertion rather than an input: the payload is
always rebuilt from the entry's own stored expiration, and a disagreement is an
error. It exists so a caller can state the expiration it believes the entry
carries and be told when that is wrong.

Results go to stdout; errors go to stderr. With --json the report is a single
object for one entry, or an array of objects with operation_index and
entry_index for an envelope; a usage or decode error is a JSON object with an
"error" field on stdout, as in the other subcommands.

Nothing is signed and no key is involved.

What a green result does and does not guarantee — custom accounts, expiration,
nonce consumption — is stated in docs/verification-limits.md in the source
repository.
`

// verifyNodeOutput is one credential node's verdict in the JSON report.
type verifyNodeOutput struct {
	Address string `json:"address"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// verifyEntryOutput is one entry's verification report in the JSON output.
type verifyEntryOutput struct {
	OperationIndex   int                `json:"operation_index,omitempty"`
	EntryIndex       int                `json:"entry_index,omitempty"`
	CredentialType   string             `json:"credential_type"`
	AddressBound     bool               `json:"address_bound"`
	Address          string             `json:"address,omitempty"`
	ValidUntilLedger uint32             `json:"valid_until_ledger,omitempty"`
	Verified         bool               `json:"verified"`
	Nodes            []verifyNodeOutput `json:"nodes"`
	Note             string             `json:"note,omitempty"`
}

func newVerifyEntryOutput(report soroauth.VerificationReport) verifyEntryOutput {
	out := verifyEntryOutput{
		CredentialType:   report.CredentialType,
		AddressBound:     report.AddressBound,
		Address:          report.Address,
		ValidUntilLedger: report.ValidUntilLedger,
		Verified:         report.Verified(),
		Note:             report.Note,
		Nodes:            make([]verifyNodeOutput, 0, len(report.Nodes)),
	}
	for _, node := range report.Nodes {
		out.Nodes = append(out.Nodes, verifyNodeOutput{
			Address: node.Address,
			Verdict: string(node.Verdict),
			Reason:  node.Reason,
		})
	}
	return out
}

// verifyFailed reports whether a report has a node that is not a pass.
//
// It is the fail-closed reading of the report: cannot_check is a failure
// because the command cannot say the entry is good, and unsigned is a failure
// unless the operator has said their policy accepts it (--allow-unsigned).
func verifyFailed(report soroauth.VerificationReport, allowUnsigned bool) bool {
	for _, node := range report.Nodes {
		switch node.Verdict {
		case soroauth.VerdictVerified:
		case soroauth.VerdictUnsigned:
			if !allowUnsigned {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func runVerify(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, verifyUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	configFlag := flags.String("config", "", "path to CLI configuration file (default $SOROAUTH_CONFIG or ~/.config/soroauth/config.json)")
	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	entriesFlag := flags.String("entries", "", "a file of entries to verify, one base64 entry per line, or - for stdin")
	networkFlag := flags.String("network", "", "testnet, futurenet, public, or a literal network passphrase")
	validUntil := flags.Uint("valid-until", 0, "assert the expiration the entry carries (optional)")
	allowUnsigned := flags.Bool("allow-unsigned", false, "accept unsigned nodes (a Void top-level node of a delegates entry is legitimate under CAP-71-01)")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	set := visitedFlags(flags)
	cfg, err := loadConfig(*configFlag, getenv)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	jsonMode, err := resolveJSONMode(set, *jsonFlag, getenv, cfg)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	resolvedNet := resolveNetworkValue(set, *networkFlag, getenv, cfg).Value

	if *entryFlag != "" && *entriesFlag != "" {
		return writeJSONError(stdout, jsonMode,
			newErrorf(ExitUsageError, "--entry and --entries are mutually exclusive"))
	}
	if *entriesFlag != "" {
		return runVerifyBatch(stdout, stderr, *entriesFlag, stdin,
			resolvedNet, *validUntil, *allowUnsigned, jsonMode)
	}
	if *entryFlag == "" {
		return writeJSONError(stdout, jsonMode,
			newErrorf(ExitUsageError, "--entry or --entries is required"))
	}

	input, err := decodeEntryOrEnvelopeFrom(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}
	passphrase, err := resolveNetwork(resolvedNet)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	// Gather the entries to verify, with their position when they came from
	// an envelope. A source-account entry is kept rather than skipped: its
	// report explains why there is nothing to check, and dropping it would
	// make the output's shape depend on the arm.
	type located struct {
		entry          xdr.SorobanAuthorizationEntry
		operationIndex int
		entryIndex     int
	}

	var locatedEntries []located
	if input.IsEnvelope {
		entries, err := soroauth.EnvelopeEntries(input.Envelope)
		if err != nil {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "%w", err))
		}
		for _, e := range entries {
			locatedEntries = append(locatedEntries, located{entry: e.Entry, operationIndex: e.OperationIndex, entryIndex: e.EntryIndex})
		}
	} else {
		locatedEntries = append(locatedEntries, located{entry: input.Entry})
	}

	outputs := make([]verifyEntryOutput, 0, len(locatedEntries))
	failed := false
	for _, item := range locatedEntries {
		report, err := soroauth.VerifyEntry(item.entry, passphrase)
		if err != nil {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitVerificationFailed, "%w", err))
		}
		if *validUntil != 0 && report.ValidUntilLedger != uint32(*validUntil) {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitVerificationFailed,
				"entry carries expiration %d, but --valid-until says %d", report.ValidUntilLedger, uint32(*validUntil)))
		}

		out := newVerifyEntryOutput(report)
		if input.IsEnvelope {
			out.OperationIndex = item.operationIndex + 1
			out.EntryIndex = item.entryIndex + 1
		}
		outputs = append(outputs, out)
		if verifyFailed(report, *allowUnsigned) {
			failed = true
		}
	}

	if jsonMode {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if input.IsEnvelope {
			if err := enc.Encode(outputs); err != nil {
				return newErrorf(ExitGeneralError, "encoding the report: %w", err)
			}
		} else if err := enc.Encode(outputs[0]); err != nil {
			return newErrorf(ExitGeneralError, "encoding the report: %w", err)
		}
	} else {
		writeVerifyText(stdout, outputs, input.IsEnvelope)
	}

	if failed {
		return newErrorf(ExitVerificationFailed, "one or more credential nodes did not verify")
	}
	return nil
}

// runVerifyBatch applies verify to every input in the file, with the same
// per-entry handling the usage text describes: every input is attempted, each
// outcome carries its position, and the exit code is the FIRST failure's.
func runVerifyBatch(stdout, stderr io.Writer, entriesFlag string, stdin io.Reader, networkFlag string, validUntil uint, allowUnsigned, jsonFlag bool) error {
	passphrase, err := resolveNetwork(networkFlag)
	if err != nil {
		return writeJSONError(stdout, jsonFlag, err)
	}

	inputs, err := readBatchEntries("--entries", entriesFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonFlag, err)
	}
	if len(inputs) == 0 {
		return writeJSONError(stdout, jsonFlag, emptyBatchError("--entries", entriesFlag))
	}

	run := newBatchRun(len(inputs))
	for _, in := range inputs {
		if in.Err != nil {
			run.fail(in.Index, in.Err)
			reportBatchFailure(stderr, jsonFlag, in.Index, in.Err)
			continue
		}

		report, err := soroauth.VerifyEntry(in.Entry, passphrase)
		if err != nil {
			failure := newErrorf(ExitVerificationFailed, "%w", err)
			run.fail(in.Index, failure)
			reportBatchFailure(stderr, jsonFlag, in.Index, failure)
			continue
		}
		if validUntil != 0 && report.ValidUntilLedger != uint32(validUntil) {
			failure := newErrorf(ExitVerificationFailed,
				"entry carries expiration %d, but --valid-until says %d", report.ValidUntilLedger, uint32(validUntil))
			run.fail(in.Index, failure)
			reportBatchFailure(stderr, jsonFlag, in.Index, failure)
			continue
		}

		out := newVerifyEntryOutput(report)
		// A verdict that is not a pass still has a report worth printing,
		// so it stays a result and only the exit code records the failure.
		if verifyFailed(report, allowUnsigned) {
			run.recordFailure(newErrorf(ExitVerificationFailed, "one or more credential nodes did not verify"))
		}
		run.result(in.Index, out)
		if !jsonFlag {
			fmt.Fprintf(stdout, "entry %d:\n", in.Index)
			writeVerifyText(stdout, []verifyEntryOutput{out}, false)
		}
	}

	return run.finish(stdout, jsonFlag)
}

// writeVerifyText renders the reports for a human, one line per node.
func writeVerifyText(stdout io.Writer, outputs []verifyEntryOutput, envelope bool) {
	for _, out := range outputs {
		if envelope {
			fmt.Fprintf(stdout, "operation %d entry %d: %s\n", out.OperationIndex, out.EntryIndex, out.CredentialType)
		} else {
			fmt.Fprintf(stdout, "%s\n", out.CredentialType)
		}
		if out.Address != "" {
			fmt.Fprintf(stdout, "  address: %s\n", out.Address)
		}
		if out.ValidUntilLedger != 0 {
			fmt.Fprintf(stdout, "  valid until ledger: %d\n", out.ValidUntilLedger)
		}
		if out.Note != "" {
			fmt.Fprintf(stdout, "  note: %s\n", out.Note)
		}
		for _, node := range out.Nodes {
			if node.Reason != "" {
				fmt.Fprintf(stdout, "  %s: %s (%s)\n", node.Address, node.Verdict, node.Reason)
			} else {
				fmt.Fprintf(stdout, "  %s: %s\n", node.Address, node.Verdict)
			}
		}
		if out.Verified {
			fmt.Fprintln(stdout, "  result: verified")
		} else {
			fmt.Fprintln(stdout, "  result: NOT verified")
		}
	}
}
