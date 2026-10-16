package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

const simulateUsage = `soroauth simulate — run the record pass and print what the host recorded.

usage:
  soroauth simulate --entry <envelope|-> [--rpc-url <url>] [--use-upgraded-auth]
                    [--timeout <duration>] [--json]

--entry is a transaction envelope (or - for stdin), not an authorization
entry: simulation is what produces entries, so there is nothing to hand it yet.
The record pass answers which addresses must authorize the call; it does not
sign anything and needs no key and no network passphrase.

The endpoint is --rpc-url or, if that is unset, $SOROAUTH_RPC_URL. There is no
default endpoint: a simulation is the input to a signature that moves value, so
the chain it runs against should be the caller's explicit choice.

Each recorded entry is printed as base64 with the operation index and entry
index it belongs to, and the arm the host actually recorded is reported as it
was decoded from the response — asking for --use-upgraded-auth is best-effort,
and a host that recorded the legacy arm is reported that way rather than as the
arm that was requested. The minimum resource fee, the SorobanTransactionData
and the ledger the pass ran against follow, and then the envelope to hand to
the next step:

  soroauth simulate --entry tx.b64 --json > recorded.json
  ... sign the entries ...
  soroauth submit --entry <the envelope simulate printed> --secret-env PAYER --network testnet

The envelope printed is the input envelope with the recorded entries attached,
because that is what "sign an entry" needs to be given: signing a bare entry
produces a bare entry, and assembling one back into a transaction by hand is
the part of the two-pass flow people get wrong.

With --json, prints one object with fields "entries" (each an object with
"operation_index", "entry_index", "arm" and "entry"), "min_resource_fee",
"transaction_data", "latest_ledger" and "envelope". On error, prints a JSON
object with field "error" to stdout and exits non-zero.

exit codes:
  0  success
  1  general error (the RPC could not be reached, or the host refused the simulation)
  2  usage error (missing flags, or --entry is not a transaction envelope)
`

// defaultSimulateTimeout bounds a record pass. A simulation is a read-only
// call against a service that is expected to answer in well under a second, so
// waiting minutes on one helps nobody; a caller on a slow endpoint raises it.
const defaultSimulateTimeout = 30 * time.Second

// simulateEntryOutput is one recorded entry, with the position it came from.
type simulateEntryOutput struct {
	OperationIndex int    `json:"operation_index"`
	EntryIndex     int    `json:"entry_index"`
	Arm            string `json:"arm"`
	Entry          string `json:"entry"`
}

// simulateOutput is the --json success object.
type simulateOutput struct {
	Entries         []simulateEntryOutput `json:"entries"`
	MinResourceFee  int64                 `json:"min_resource_fee"`
	TransactionData string                `json:"transaction_data,omitempty"`
	LatestLedger    uint32                `json:"latest_ledger"`
	Envelope        string                `json:"envelope"`
}

func runSimulate(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("simulate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, simulateUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the transaction envelope to simulate, as base64 XDR or - for stdin")
	rpcURL := flags.String("rpc-url", "", "RPC endpoint to simulate against (default $SOROAUTH_RPC_URL)")
	upgraded := flags.Bool("use-upgraded-auth", false,
		"ask the host to record the address-bound V2 arm (best-effort; the recorded arm is reported as it was)")
	timeout := flags.Duration("timeout", defaultSimulateTimeout, "how long to wait for the simulation")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	if *entryFlag == "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--entry is required"))
	}

	endpoint := resolveRPCURL(*rpcURL, getenv)
	if endpoint == "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"simulating needs an RPC endpoint: pass --rpc-url <url> or set SOROAUTH_RPC_URL"))
	}

	value, err := readEntryFlagFrom(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "%w", err))
	}

	// The envelope is decoded here rather than only inside rpcflow so a blob
	// that is not a transaction envelope — an entry, say, which is the mistake
	// this flag invites — is reported as a usage error naming the flag rather
	// than as a simulation failure.
	if _, err := soroauth.DecodeTransactionEnvelope(value); err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"decoding --entry as a transaction envelope: %w",
			classifyInput(value, "a transaction envelope", err)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := rpcclient.NewClient(endpoint, nil)
	defer func() { _ = client.Close() }()

	record, err := rpcflow.SimulateRecord(ctx, rpcflow.RecordParams{
		Client:          client,
		EnvelopeXDR:     value,
		UseUpgradedAuth: *upgraded,
	})
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(exitCodeForSimulateError(err), "%w", err))
	}

	out := simulateOutput{
		Entries:         make([]simulateEntryOutput, 0, len(record.Entries)),
		MinResourceFee:  record.MinResourceFee,
		TransactionData: record.TransactionDataXDR,
		LatestLedger:    record.LatestLedger,
		Envelope:        record.EnvelopeXDR,
	}
	for _, entry := range record.Entries {
		encoded, err := encodeEntry(entry.Entry)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
		}
		out.Entries = append(out.Entries, simulateEntryOutput{
			OperationIndex: entry.OperationIndex,
			EntryIndex:     entry.EntryIndex,
			Arm:            entry.Arm,
			Entry:          encoded,
		})
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	for _, entry := range out.Entries {
		fmt.Fprintf(stdout, "operation %d entry %d: %s\n", entry.OperationIndex, entry.EntryIndex, entry.Arm)
		fmt.Fprintln(stdout, entry.Entry)
	}
	fmt.Fprintf(stdout, "min_resource_fee: %d\n", out.MinResourceFee)
	fmt.Fprintf(stdout, "transaction_data: %s\n", out.TransactionData)
	fmt.Fprintf(stdout, "latest_ledger: %d\n", out.LatestLedger)
	fmt.Fprintf(stdout, "envelope: %s\n", out.Envelope)
	return nil
}

// exitCodeForSimulateError separates the failures that are the caller's input
// from the ones that are the endpoint's. A malformed envelope and an envelope
// with nothing to authorize are usage errors — no retry against the same input
// can succeed — while a refusal or an unreachable endpoint is a general error.
func exitCodeForSimulateError(err error) int {
	switch {
	case errors.Is(err, soroauth.ErrDecodeLimit),
		errors.Is(err, soroauth.ErrNoInvokeOperation):
		return ExitUsageError
	default:
		return ExitGeneralError
	}
}
