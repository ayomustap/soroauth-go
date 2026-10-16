package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
)

const inspectUsage = `soroauth inspect — print an entry's structure as JSON.

usage:
  soroauth inspect --entry <base64>|[-] [--json]
  soroauth inspect --entries <file|-> [--json]

--entry accepts either an authorization entry or a whole transaction envelope,
and the tool works out which it was given. An envelope is reported as an array,
one object per authorization entry, each with the operation_index and
entry_index it came from; a fee-bump envelope is read through to the inner
transaction, so the indices are indices into the inner transaction's
operations. A single entry is reported as one object, as it always has been.

--entries reads many entries: one base64 authorization entry per line from the
named file ("-" for stdin), blank lines skipped. Each input is reported with
its 1-based position: an "entry N:" header and the same report as a single
entry without --json, or one array element per input with it —
{"entry": N, "result": {...}} on success, {"entry": N, "error": "..."} on
failure. A failing line is reported with its index and does not stop the run;
the exit code is the first failure's. Batch input takes one entry per line, not
an envelope: an envelope carries several entries, so select them first.

Reports the credential arm, whether the payload is address-bound, the address,
nonce and expiration ledger, which nodes carry signatures, the delegate tree,
and the shape of the invocation tree.

Without --json the report is pretty-printed for reading. With --json it is a
single compact object, so it composes with jq and with the other subcommands.
On error, --json prints a single JSON object with an "error" field to stdout
and exits non-zero; nothing else is written to stdout.

This is structural only. It reports which contract and function are being
called, not what they do or whether the arguments are reasonable, so it is a
check that an entry is the one you meant to submit — the right arm, the right
address, signed in the right places — and not a substitute for understanding
the call.

Nothing is signed and no key is involved.

exit codes:
  0  success
  1  general error
  2  usage error (missing --entry/--entries or malformed input)
`

func runInspect(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, inspectUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	configFlag := flags.String("config", "", "path to CLI configuration file (default $SOROAUTH_CONFIG or ~/.config/soroauth/config.json)")
	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	entriesFlag := flags.String("entries", "", "a file of entries to inspect, one base64 entry per line, or - for stdin")
	// inspect's success output is already the JSON report described above;
	// --json exists only so every subcommand accepts the same flag, and here
	// it additionally makes a usage or decode error come back as a JSON
	// object on stdout instead of plain text on stderr, matching every other
	// subcommand's --json contract.
	jsonFlag := flags.Bool("json", false, "accepted for consistency with other subcommands; inspect's output is always JSON")

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

	if *entryFlag != "" && *entriesFlag != "" {
		return writeJSONError(stdout, jsonMode,
			newErrorf(ExitUsageError, "--entry and --entries are mutually exclusive"))
	}
	if *entriesFlag != "" {
		return runInspectBatch(stdout, stderr, *entriesFlag, stdin, jsonMode)
	}
	if *entryFlag == "" {
		return writeJSONError(stdout, jsonMode,
			newErrorf(ExitUsageError, "--entry or --entries is required"))
	}

	input, err := decodeEntryOrEnvelopeFrom(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError, "%w", err))
	}

	// An envelope is reported entry by entry, each with the position it came
	// from, because that is what a caller has to line a signed entry back up
	// with. A lone entry stays a single object, so existing scripts keep
	// working.
	var report any
	if input.IsEnvelope {
		infos, err := soroauth.InspectEnvelope(input.Envelope)
		if err != nil {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "%w", err))
		}
		report = infos
	} else {
		info, err := soroauth.Inspect(input.Entry)
		if err != nil {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "%w", err))
		}
		report = info
	}

	// inspect's success output is already JSON, so --json is a true no-op
	// here: the report is always pretty-printed the same way, with or
	// without the flag, and existing scripts that called inspect before
	// --json existed keep getting byte-identical output.
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "encoding the report: %w", err))
	}
	fmt.Fprintln(stdout, string(encoded))
	return nil
}

// runInspectBatch applies inspect to every input in the file. The report per
// input is the same one inspect prints for a single entry; the batch wrapper
// only adds the index and the per-input error handling described in the usage
// text.
func runInspectBatch(stdout, stderr io.Writer, entriesFlag string, stdin io.Reader, jsonFlag bool) error {
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

		info, err := soroauth.Inspect(in.Entry)
		if err != nil {
			failure := newErrorf(ExitGeneralError, "%w", err)
			run.fail(in.Index, failure)
			reportBatchFailure(stderr, jsonFlag, in.Index, failure)
			continue
		}

		run.result(in.Index, info)
		if !jsonFlag {
			encoded, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				return newErrorf(ExitGeneralError, "encoding the report: %w", err)
			}
			fmt.Fprintf(stdout, "entry %d:\n%s\n", in.Index, string(encoded))
		}
	}

	return run.finish(stdout, jsonFlag)
}
