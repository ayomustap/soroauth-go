package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const treeUsage = `soroauth tree — render an entry's delegate tree.

usage:
  soroauth tree --entry <base64> [--format ascii|dot] [--json]

--entry accepts either an authorization entry or a whole transaction envelope,
same as inspect and payload; an envelope is rendered as one tree per
authorization entry, in operation order.

Every credentials arm has a top-level node, and the delegates arm
(SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES, CAP-71-01) adds a tree of
delegate nodes beneath it. Each node shows its address and whether it carries
a signature. One address appearing at more than one nesting level is legal
under CAP-71-01 and is printed once per occurrence rather than merged into a
single node, since each occurrence is a distinct node with its own signature.

--format ascii (the default) prints an indented tree for a terminal.
--format dot prints a Graphviz digraph, for embedding in documentation:

  soroauth tree --entry <base64> --format dot | dot -Tsvg -o tree.svg

With --json, prints structured output instead of either rendering: for a
single entry, a JSON object with the same shape as "soroauth inspect"
(credential_type, address, top_level_signed, delegates, ...); for an
envelope, an array of those objects, each with operation_index and
entry_index. --json and --format are independent: --format is ignored when
--json is set, since the JSON output is the structure the renderers are built
from, not a rendering of it. On error, prints a JSON object with field
"error" to stdout and exits non-zero.

exit codes:
  0  success
  1  general error
  2  usage error (missing --entry, malformed input, or an unknown --format)
`

func runTree(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	flags := flag.NewFlagSet("tree", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, treeUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	configFlag := flags.String("config", "", "path to CLI configuration file (default $SOROAUTH_CONFIG or ~/.config/soroauth/config.json)")
	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	formatFlag := flags.String("format", "ascii", "tree rendering: ascii or dot")
	jsonFlag := flags.Bool("json", false, "output structured JSON instead of a rendering")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	set := visitedFlags(flags)
	cfg, err := loadConfig(*configFlag, getenv)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	if set["format"] && *formatFlag != "ascii" && *formatFlag != "dot" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--format must be ascii or dot, got %q", *formatFlag))
	}

	fmtRes, err := resolveFormatValue(set, *formatFlag, *jsonFlag, getenv, cfg, "ascii")
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	jsonMode := *jsonFlag || fmtRes.Value == "json"
	effectiveFormat := fmtRes.Value
	if effectiveFormat == "text" || effectiveFormat == "json" {
		effectiveFormat = "ascii"
	}
	if set["format"] {
		effectiveFormat = *formatFlag
	}

	input, err := decodeEntryOrEnvelope(*entryFlag)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	if input.IsEnvelope {
		return runTreeEnvelope(stdout, input.Envelope, effectiveFormat, jsonMode)
	}

	info, err := soroauth.Inspect(input.Entry)
	if err != nil {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "%w", err))
	}

	if jsonMode {
		return writeJSON(stdout, info)
	}
	fmt.Fprint(stdout, renderTree(info, effectiveFormat))
	return nil
}

// runTreeEnvelope reports every authorization entry in an envelope, in
// operation order: one tree (or JSON object) per entry, each preceded by the
// position it came from, matching how "inspect" reports an envelope.
func runTreeEnvelope(stdout io.Writer, envelope xdr.TransactionEnvelope, format string, jsonFlag bool) error {
	infos, err := soroauth.InspectEnvelope(envelope)
	if err != nil {
		return writeJSONError(stdout, jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}

	if jsonFlag {
		return writeJSON(stdout, infos)
	}

	for _, info := range infos {
		fmt.Fprintf(stdout, "operation %d entry %d:\n", info.OperationIndex, info.EntryIndex)
		fmt.Fprint(stdout, renderTree(info.EntryInfo, format))
		fmt.Fprintln(stdout)
	}
	return nil
}

// renderTree dispatches to the ASCII or DOT renderer. format is validated by
// the caller before any output is written, so this never sees a third value.
func renderTree(info soroauth.EntryInfo, format string) string {
	if format == "dot" {
		return soroauth.DelegateTreeDOT(info)
	}
	return soroauth.DelegateTreeASCII(info)
}

// writeJSON encodes v as indented JSON to stdout, matching the formatting
// "inspect" already uses so scripts see one consistent shape across
// subcommands.
func writeJSON(stdout io.Writer, v any) error {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return newErrorf(ExitGeneralError, "encoding the report: %w", err)
	}
	fmt.Fprintln(stdout, string(encoded))
	return nil
}
