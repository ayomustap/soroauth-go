package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
)

const diffUsage = `soroauth diff — compare two authorization entries and report what changed.

usage:
  soroauth diff --before <base64>|[-] --after <base64>|[-] [--json]
  soroauth diff --before-entries <file|-> --after-entries <file|-> [--json]

Reports the difference between two entries, and — the reason this exists —
separates the changes that invalidate signatures from the ones that do not.

Under CAP-71-01 every credential node of an entry commits to the same payload,
and that payload includes the expiration ledger, the nonce, the invocation tree,
the credential arm, and (for the address-bound arms) the address. A change to
any of those invalidates every signature made against the old entry, even
signatures whose own bytes were never touched. Those are listed as stale: the
entry reads as signed and is rejected by the host rather than locally.

The delegate tree is not part of the payload, so adding or removing a delegate
does not invalidate anyone's signature.

--before-entries and --after-entries compare many pairs: each file has one
base64 authorization entry per line (blank lines skipped, "-" for stdin, one
side only), and the Nth non-blank lines of the two files are compared as a
pair. The two files must hold the same number of entries. Each pair is
reported with its 1-based position: an "entry N:" header and the same report
as a single comparison without --json, or one array element per pair with it.
A pair whose report carries stale signatures is a failure, as for a single
comparison, and the exit code is the first failure's.

Each change is marked with "!" when it is inside the signed payload.

Without --json the report is written for reading, verdict first. With --json it
is a single object carrying the same verdict in its "summary" field. On error,
--json prints a JSON object with an "error" field to stdout and exits non-zero.

This compares the entries only. The network passphrase is the one part of the
signing payload an entry does not carry, so two entries that differ in nothing
here still have different payloads on different networks; the report says so.

Nothing is signed and no key is involved.

exit codes:
  0  the entries were compared and no signature went stale
  1  general error
  2  usage error (missing --before/--after or --before-entries/--after-entries, or malformed input)
  4  the payload changed and at least one signature was carried over unchanged
`

// runDiffBatch pairs the Nth non-blank lines of two batch files and reports
// each pair like a single comparison. A malformed side of a pair is reported
// with the flag that read it, because with two files "entry 3" alone would not
// say which file's line is wrong.
func runDiffBatch(stdout, stderr io.Writer, beforeName, afterName string, stdin io.Reader, jsonFlag bool) error {
	beforeInputs, err := readBatchEntries("--before-entries", beforeName, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonFlag, err)
	}
	if len(beforeInputs) == 0 {
		return writeJSONError(stdout, jsonFlag, emptyBatchError("--before-entries", beforeName))
	}
	afterInputs, err := readBatchEntries("--after-entries", afterName, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonFlag, err)
	}
	if len(afterInputs) == 0 {
		return writeJSONError(stdout, jsonFlag, emptyBatchError("--after-entries", afterName))
	}
	if len(beforeInputs) != len(afterInputs) {
		return writeJSONError(stdout, jsonFlag, newErrorf(ExitUsageError,
			"--before-entries (%s) has %d entries but --after-entries (%s) has %d; batch diff compares them pairwise in order",
			batchSourceName(beforeName), len(beforeInputs), batchSourceName(afterName), len(afterInputs)))
	}

	run := newBatchRun(len(beforeInputs))
	for i := range beforeInputs {
		index := i + 1

		if beforeInputs[i].Err != nil {
			failure := labelBatchError("--before-entries", beforeInputs[i].Err)
			run.fail(index, failure)
			reportBatchFailure(stderr, jsonFlag, index, failure)
			continue
		}
		if afterInputs[i].Err != nil {
			failure := labelBatchError("--after-entries", afterInputs[i].Err)
			run.fail(index, failure)
			reportBatchFailure(stderr, jsonFlag, index, failure)
			continue
		}

		report, err := soroauth.DiffEntries(beforeInputs[i].Entry, afterInputs[i].Entry)
		if err != nil {
			failure := newErrorf(ExitGeneralError, "%w", err)
			run.fail(index, failure)
			reportBatchFailure(stderr, jsonFlag, index, failure)
			continue
		}

		// A stale signature is a finding, not a tool failure: the report is a
		// result like any other, and only the exit code records the verdict.
		if len(report.StaleSignatures) > 0 {
			run.recordFailure(newErrorf(ExitVerificationFailed,
				"%d signature(s) carried over unchanged across a payload change", len(report.StaleSignatures)))
		}
		run.result(index, report)
		if !jsonFlag {
			fmt.Fprintf(stdout, "entry %d:\n%s\n", index, report.String())
		}
	}

	return run.finish(stdout, jsonFlag)
}

func runDiff(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, diffUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	configFlag := flags.String("config", "", "path to CLI configuration file (default $SOROAUTH_CONFIG or ~/.config/soroauth/config.json)")
	beforeFlag := flags.String("before", "", "the first authorization entry, as base64 XDR")
	afterFlag := flags.String("after", "", "the second authorization entry, as base64 XDR")
	beforeEntriesFlag := flags.String("before-entries", "", "a file of entries to compare, one base64 entry per line, or - for stdin; paired with --after-entries")
	afterEntriesFlag := flags.String("after-entries", "", "a file of entries to compare, one base64 entry per line, or - for stdin; paired with --before-entries")
	jsonFlag := flags.Bool("json", false, "print the report as a single JSON object")

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

	if *beforeEntriesFlag != "" || *afterEntriesFlag != "" {
		if *beforeFlag != "" || *afterFlag != "" {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
				"--before/--after and --before-entries/--after-entries are mutually exclusive"))
		}
		if *beforeEntriesFlag == "" {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
				"--before-entries is required with --after-entries"))
		}
		if *afterEntriesFlag == "" {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
				"--after-entries is required with --before-entries"))
		}
		if *beforeEntriesFlag == "-" && *afterEntriesFlag == "-" {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
				"only one of --before-entries and --after-entries can be read from stdin"))
		}
		return runDiffBatch(stdout, stderr, *beforeEntriesFlag, *afterEntriesFlag, stdin, jsonMode)
	}

	if *beforeFlag == "" {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
			"--before or --before-entries is required"))
	}
	if *afterFlag == "" {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
			"--after or --after-entries is required"))
	}

	// Only one side can come from stdin, since there is one stream. Saying so
	// is better than reading the same blob twice and reporting two identical
	// entries, which would look like a successful comparison.
	if *beforeFlag == "-" && *afterFlag == "-" {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
			"only one of --before and --after can be read from stdin"))
	}

	before, err := decodeEntryNamedFrom("--before", *beforeFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}
	after, err := decodeEntryNamedFrom("--after", *afterFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	report, err := soroauth.DiffEntries(before, after)
	if err != nil {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "%w", err))
	}

	if jsonMode {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return writeJSONError(stdout, true, newErrorf(ExitGeneralError, "encoding the report: %w", err))
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprint(stdout, report.String())
	}

	// A stale signature is a finding, not a tool failure, so the report is
	// printed in full first and the exit code carries the verdict — the same
	// contract `verify` uses, so one script can treat both the same way.
	if len(report.StaleSignatures) > 0 {
		return newErrorf(ExitVerificationFailed,
			"%d signature(s) carried over unchanged across a payload change", len(report.StaleSignatures))
	}
	return nil
}
