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
	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

const submitUsage = `soroauth submit — enforce, sign, send and poll a transaction.

usage:
  soroauth submit --entry <envelope|-> --network <name|passphrase> \
                  --secret-env <VAR> [--rpc-url <url>] [--allow-unsigned] \
                  [--timeout <duration>] [--json]

--entry is a transaction envelope carrying the signed authorization entries
(or - for stdin), the shape "soroauth simulate" prints. It is run through the
enforcing pass first, so the resource fee the transaction is submitted with
covers the signatures: a fee computed before they existed is too small, and the
transaction is then accepted, charged for, and fails during application. That
is the step this subcommand exists to make hard to skip.

The envelope's own signature is made with the seed in the environment variable
named by --secret-env — never a flag value, which would put a secret in shell
history and in the process table. The seed must be the envelope's source
account's, because that is the account that pays and supplies the sequence.

Every address-arm entry is checked before anything is submitted, and one with
an unsigned node is refused rather than sent to fail on-chain and cost a fee.
The exception is a delegates entry's top-level node, which CAP-71-01 permits to
stay Void when every delegate authenticates. --allow-unsigned overrides the
refusal for what this tool cannot judge — a custom account's own __check_auth
decides its signature shape — but nothing is ever reported as valid that was
not checked.

The transaction hash is printed the moment the RPC accepts the transaction for
submission, before it is polled, so a poll that times out or is interrupted
still leaves something to look up. With --json the hash goes to stderr and
stdout stays a single JSON object written at the end.

On a terminal failure the host's own result XDR and diagnostic events are
printed as they were returned, never paraphrased, and the exit code is
non-zero.

exit codes:
  0  success
  1  general error (unreachable endpoint, or the transaction failed on-chain)
  2  usage error (missing flags, an unsigned entry, or --entry is not an envelope)
`

// defaultSubmitTimeout bounds the whole submit: the enforcing pass, the send
// and the poll. A ledger closes every few seconds and a transaction is normally
// included within a handful of them, so a minute is generous; the flag exists
// because the failure a longer wait avoids is an interrupted poll on a
// transaction that is already on its way.
const defaultSubmitTimeout = 60 * time.Second

// submitOutput is the --json success object, and the failure object too: a
// failed submission is an outcome, not a call failure, so it carries the same
// fields plus the host's own result.
type submitOutput struct {
	Hash        string   `json:"hash"`
	Status      string   `json:"status"`
	Ledger      uint32   `json:"ledger,omitempty"`
	Arm         string   `json:"arm,omitempty"`
	ResultXDR   string   `json:"result_xdr,omitempty"`
	Diagnostics []string `json:"diagnostic_events,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// submitRequest is the transaction a submit runs over, taken out of the
// envelope it was handed.
type submitRequest struct {
	Source    txnbuild.Account
	Operation txnbuild.InvokeHostFunction
	Entries   []xdr.SorobanAuthorizationEntry
	BaseFee   int64
}

func runSubmit(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, submitUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the signed transaction envelope, as base64 XDR or - for stdin")
	networkFlag := flags.String("network", "", "testnet, futurenet, public, or a literal network passphrase")
	secretEnv := flags.String("secret-env", "", "name of the environment variable holding the source account's seed (S…)")
	rpcURL := flags.String("rpc-url", "", "RPC endpoint to submit to (default $SOROAUTH_RPC_URL)")
	allowUnsigned := flags.Bool("allow-unsigned", false,
		"submit even though an address entry is unsigned (the host will refuse it)")
	timeout := flags.Duration("timeout", defaultSubmitTimeout, "how long to wait for the enforcing pass, the send and the poll")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	switch {
	case *entryFlag == "":
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--entry is required"))
	case *secretEnv == "":
		// The envelope's signature is the source account's, so there is no
		// path here that submits without one; saying so beats failing later
		// with a message about a missing signature.
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"--secret-env is required: the transaction envelope is signed with the source account's seed"))
	}

	// The endpoint is resolved before the seed is read: both are usage errors,
	// and the one that does not touch a secret is the cheaper one to report
	// first.
	endpoint := resolveRPCURL(*rpcURL, getenv)
	if endpoint == "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"submitting needs an RPC endpoint: pass --rpc-url <url> or set SOROAUTH_RPC_URL"))
	}

	passphrase, err := resolveNetwork(*networkFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	envelopeKey, err := resolveSeedKeypair(getenv, *secretEnv)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	value, err := readEntryFlagFrom(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "%w", err))
	}

	envelope, err := soroauth.DecodeTransactionEnvelope(value)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"decoding --entry as a transaction envelope: %w",
			classifyInput(value, "the signed transaction envelope", err)))
	}

	request, err := submitInputs(envelope)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "%w", err))
	}

	if !*allowUnsigned {
		if address := unsignedRefusal(request.Entries, passphrase); address != "" {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
				"refusing to submit: the entry for %s is unsigned, so the transaction would be "+
					"refused on-chain and its fee still spent; sign it first, or pass --allow-unsigned "+
					"to send it anyway", address))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := rpcclient.NewClient(endpoint, nil)
	defer func() { _ = client.Close() }()

	// The hash is announced the moment the RPC accepts the submission and
	// before the poll: a poll that never returns must not be the reason a
	// caller cannot find its transaction. In JSON mode the announcement goes to
	// stderr so stdout stays a single object.
	var sentHash string
	sub, err := rpcflow.Submit(ctx, rpcflow.SubmitParams{
		Source:            request.Source,
		Operation:         request.Operation,
		Entries:           request.Entries,
		EnvelopeSigners:   []*keypair.Full{envelopeKey},
		NetworkPassphrase: passphrase,
		Client:            client,
		BaseFee:           request.BaseFee,
		OnSent: func(sent rpcflow.Submission) {
			sentHash = sent.Hash
			if *jsonFlag {
				fmt.Fprintf(stderr, "soroauth: submitted %s (%s), polling\n", sent.Hash, sent.Status)
				return
			}
			fmt.Fprintf(stdout, "hash: %s\n", sent.Hash)
		},
	})
	if err != nil {
		if sentHash != "" {
			// The transaction is already on its way, so the hash is the one
			// thing that must survive the failure.
			err = fmt.Errorf("%w (the rpc had already accepted %s; look that hash up before resubmitting)", err, sentHash)
		}
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}

	out := submitOutput{
		Hash:        sub.Hash,
		Status:      sub.Status,
		Ledger:      sub.Ledger,
		Arm:         sub.Arm,
		ResultXDR:   sub.RawError,
		Diagnostics: sub.Diagnostics,
	}

	if sub.Status != rpc.TransactionStatusSuccess {
		out.Error = failureText(sub)
		if *jsonFlag {
			enc := json.NewEncoder(stdout)
			enc.SetEscapeHTML(false)
			if encodeErr := enc.Encode(out); encodeErr != nil {
				return newErrorf(ExitGeneralError, "encoding the report: %w", encodeErr)
			}
			// The report is the output; returning it as a handled JSON error
			// keeps main() from printing a second copy to stderr and still
			// exits non-zero.
			return &jsonErrorHandled{errors.New(out.Error)}
		}
		fmt.Fprintf(stdout, "status: %s\n", sub.Status)
		fmt.Fprintf(stdout, "ledger: %d\n", sub.Ledger)
		fmt.Fprintf(stdout, "arm:    %s\n", sub.Arm)
		writeFailure(stdout, sub)
		return newErrorf(ExitGeneralError, "%s", out.Error)
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}
	if sentHash == "" {
		fmt.Fprintf(stdout, "hash: %s\n", sub.Hash)
	}
	fmt.Fprintf(stdout, "status: %s\n", sub.Status)
	fmt.Fprintf(stdout, "ledger: %d\n", sub.Ledger)
	fmt.Fprintf(stdout, "arm:    %s\n", sub.Arm)
	return nil
}

// submitInputs pulls the source account, the invoke operation and the
// authorization entries out of a decoded envelope, using the envelope's own
// per-operation fee so the submitted transaction is priced the way its author
// priced it.
//
// A fee-bump envelope is refused: the fee-bump's fee source pays, and it is
// neither the inner transaction's source account nor the account whose
// sequence number the inner transaction consumes, so there is no single
// account here that this command could sign for correctly. Refusing is the
// fail-closed reading; a caller with a fee bump submits through the library.
func submitInputs(envelope xdr.TransactionEnvelope) (submitRequest, error) {
	var request submitRequest

	if envelope.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
		return request, fmt.Errorf(
			"a fee-bump envelope is not supported: its fee source is not the account this command signs for")
	}
	if envelope.Type != xdr.EnvelopeTypeEnvelopeTypeTx || envelope.V1 == nil {
		return request, fmt.Errorf("the envelope is not a transaction envelope")
	}

	tx := &envelope.V1.Tx

	index := -1
	for i := range tx.Operations {
		if tx.Operations[i].Body.Type != xdr.OperationTypeInvokeHostFunction {
			continue
		}
		if index >= 0 {
			return request, fmt.Errorf(
				"the envelope carries more than one invokeHostFunction operation, want exactly one")
		}
		index = i
	}
	if index < 0 {
		return request, fmt.Errorf("the envelope carries no invokeHostFunction operation")
	}
	if tx.Operations[index].Body.InvokeHostFunctionOp == nil {
		return request, fmt.Errorf("operation %d: the invokeHostFunction arm is empty", index)
	}

	op := tx.Operations[index]
	invoke := op.Body.InvokeHostFunctionOp

	request.Source = &txnbuild.SimpleAccount{
		AccountID: tx.SourceAccount.Address(),
		Sequence:  int64(tx.SeqNum),
	}
	request.Operation = txnbuild.InvokeHostFunction{
		HostFunction: invoke.HostFunction,
		Auth:         invoke.Auth,
		Ext:          tx.Ext,
	}
	if op.SourceAccount != nil {
		request.Operation.SourceAccount = op.SourceAccount.Address()
	}
	request.Entries = invoke.Auth

	if count := int64(len(tx.Operations)); count > 0 {
		request.BaseFee = int64(tx.Fee) / count
	}
	return request, nil
}

// unsignedRefusal returns the address of the first credential node that must
// carry a signature and does not, or "" when every entry may be submitted as it
// stands.
//
// The one exception is a delegates entry's top-level node: CAP-71-01 permits a
// Void signature there when every delegate authenticates, so only the delegates
// are required to be signed. A node whose verdict is cannot_check is not a
// refusal — a custom account decides its own signature shape, and refusing the
// submissions this tool cannot judge would make smart accounts unusable.
func unsignedRefusal(entries []xdr.SorobanAuthorizationEntry, passphrase string) string {
	for _, entry := range entries {
		report, err := soroauth.VerifyEntry(entry, passphrase)
		if err != nil {
			// An entry this engine cannot read at all is not evidence that it
			// is unsigned; the enforcing pass and the host are what decide it.
			continue
		}

		nodes := report.Nodes
		if report.CredentialType == soroauth.CredentialTypeAddressWithDelegates && len(nodes) > 0 {
			nodes = nodes[1:]
		}
		for _, node := range nodes {
			if node.Verdict == soroauth.VerdictUnsigned {
				return node.Address
			}
		}
	}
	return ""
}

// failureText is the one-line reason a failed submission exits non-zero. The
// host's own result XDR is carried in the report the caller reads; this is the
// message for the exit path, which must not be empty and must not invent a
// reading the host did not give.
func failureText(sub rpcflow.Submission) string {
	if sub.RawError != "" {
		return fmt.Sprintf("the transaction %s reached ledger %d with status %s; the host returned %s",
			sub.Hash, sub.Ledger, sub.Status, sub.RawError)
	}
	return fmt.Sprintf("the transaction %s reached ledger %d with status %s and no result XDR",
		sub.Hash, sub.Ledger, sub.Status)
}

// writeFailure prints the host's own result and diagnostics, labelled and
// verbatim.
func writeFailure(stdout io.Writer, sub rpcflow.Submission) {
	if sub.RawError != "" {
		fmt.Fprintf(stdout, "result_xdr: %s\n", sub.RawError)
	}
	for _, event := range sub.Diagnostics {
		fmt.Fprintf(stdout, "diagnostic_event: %s\n", event)
	}
}
