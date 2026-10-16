package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const signUsage = `soroauth sign — sign an authorization entry.

usage:
  soroauth sign --entry <base64|-> (--valid-until <ledger> | --valid-for <ledgers>) \
                --network <name|passphrase> \
                (--secret-env <VAR> | --assertion <file|-> | --signer-cmd <path>) \
                [--signer-timeout <duration>] [--rpc-url <url>] [--for <address>] \
                [--config <path>] [--json]
  soroauth sign --entries <file|-> (--valid-until <ledger> | --valid-for <ledgers>) \
                --network <name|passphrase> \
                (--secret-env <VAR> | --assertion <file|-> | --signer-cmd <path>) \
                [--signer-timeout <duration>] [--rpc-url <url>] [--config <path>] [--json]

Give exactly one of --valid-until (an absolute ledger) or --valid-for (a
lifetime in ledgers, added to the current ledger). --valid-for needs an RPC
endpoint, taken from --rpc-url, $SOROAUTH_RPC_URL, or the config file; it is
refused when none names one, because guessing a network here would sign an
expiration bound to the wrong chain.

Give exactly one of --secret-env (the name of an environment variable holding an
S… seed), --assertion (a WebAuthn assertion, from a file or - for stdin), or
--signer-cmd (an external program speaking the remote signing protocol over
stdin and stdout).

Subcommands support reading entries from stdin using --entry - so commands compose in pipelines:

  soroauth delegates --entry entry.b64 --valid-until 1234567 --delegate GABC... | \
    soroauth sign --entry - --valid-until 1234567 --network testnet --secret-env SEED --for GABC...

--entry accepts either an authorization entry or a whole transaction envelope,
and the tool works out which it was given. Given an envelope it signs every
authorization entry the envelope carries and prints the envelope back; a
fee-bump envelope is read through to its inner transaction, which is where the
entries live.

--entries signs many entries: one base64 authorization entry per line from the
named file ("-" for stdin), blank lines skipped. An envelope is not a batch
line; select its entries first. Signing a batch is all-or-nothing: if any line
fails to decode or to sign, no signed output is written at all and the exit
code is the first failure's, so a partial batch can never be mistaken for a
complete one. --for applies to a single entry and is refused with --entries.

A wallet that has just signed entries must run a second simulation in enforce
mode before submitting: signing changes what the transaction costs to run, and
a transaction assembled from the record-mode simulation will be rejected on
resource fees. This command signs entries only — it does not simulate, and it
does not sign the envelope itself, which is the source account's (or the
fee-bump fee source's) signature, not an authorization entry.

The signing seed is read from the environment variable named by --secret-env,
a WebAuthn assertion JSON is read from a file or stdin via --assertion, or
signing is delegated to an external program via --signer-cmd.
There is deliberately no flag that takes a seed or private key as a literal value:
flag values end up in shell history, in the process table, and in any transcript
of the session.

The signature is written only onto credential nodes whose address matches the
signer's own address, or the address given by --for. If no node matches, the
command fails rather than signing something else. --for applies to a single
entry and is refused for an envelope, where it would have to mean something
different per entry.

Prints the signed entry as base64, or the signed envelope as base64 when given
an envelope. With --json, prints a JSON object with field "signed_entry", or
"signed_envelope". On error, prints a JSON object with field "error" to stdout
and exits non-zero.

In batch mode each signed entry is labelled with its 1-based input position:
without --json each is preceded by an "entry N:" line, and with --json the
report is one array of {"entry": N, "result": {"signed_entry": "..."}}.
`

type signOutput struct {
	SignedEntry    string `json:"signed_entry,omitempty"`
	SignedEnvelope string `json:"signed_envelope,omitempty"`
	Error          string `json:"error,omitempty"`
}

func runSign(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	return runSignWithStdin(args, stdout, stderr, getenv, os.Stdin)
}

func runSignWithStdin(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, signUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	configFlag := flags.String("config", "", "path to CLI configuration file (default $SOROAUTH_CONFIG or ~/.config/soroauth/config.json)")
	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR or -")
	entriesFlag := flags.String("entries", "", "a file of entries to sign, one base64 entry per line, or - for stdin")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signature is valid")
	validFor := flags.Uint64("valid-for", 0, "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)")
	rpcURL := flags.String("rpc-url", "", "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)")
	networkFlag := flags.String("network", "", "testnet, futurenet, public, or a literal network passphrase")
	secretEnv := flags.String("secret-env", "", "name of the environment variable holding the signing seed (S…)")
	assertionFlag := flags.String("assertion", "", "path to a WebAuthn assertion JSON file, or - for stdin")
	signerCmd := flags.String("signer-cmd", "", "path to an external signer executable speaking the remote protocol over stdin/stdout")
	signerTimeout := flags.Duration("signer-timeout", defaultExecSignerTimeout, "timeout for the external signer executable")
	forAddress := flags.String("for", "", "credential node to sign, when it is not the signer's own address")
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

	if *entryFlag != "" && *entriesFlag != "" {
		return writeJSONError(stdout, jsonMode,
			newErrorf(ExitUsageError, "--entry and --entries are mutually exclusive"))
	}
	if *entryFlag == "" && *entriesFlag == "" {
		return writeJSONError(stdout, jsonMode,
			newErrorf(ExitUsageError, "--entry or --entries is required"))
	}
	// --for names one credential node of one entry, and a batch has many, so
	// the target would be ambiguous. Refusing is the fail-closed reading, as
	// it is for an envelope below.
	if *entriesFlag != "" && *forAddress != "" {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
			"--for applies to a single entry; it cannot be combined with --entries"))
	}

	resolvedNet := resolveNetworkValue(set, *networkFlag, getenv, cfg).Value
	passphrase, err := resolveNetwork(resolvedNet)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}
	resolvedRPC := resolveRPCURLValue(set, *rpcURL, getenv, cfg, "").Value
	expiration, err := resolveValidUntil(context.Background(), uint64(*validUntil), *validFor, resolvedRPC, fetchLatestLedger)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	effectiveSecretEnv := *secretEnv
	if !set["secret-env"] && !set["assertion"] && !set["signer-cmd"] {
		effectiveSecretEnv = resolveSecretEnvValue(set, *secretEnv, getenv, cfg).Value
	}
	signer, err := resolveSigner(getenv, effectiveSecretEnv, *assertionFlag, *signerCmd, *forAddress, *signerTimeout)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	if *entriesFlag != "" {
		return runSignBatch(stdout, *entriesFlag, stdin, signer, expiration, passphrase, jsonMode)
	}

	resolvedEntry, err := resolveEntryArg(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	input, err := decodeEntryOrEnvelopeFrom(resolvedEntry, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonMode, err)
	}

	// An envelope carries entries for whatever addresses simulation recorded,
	// so a single target address would be ambiguous: it would have to apply to
	// one of them and not the others. Refusing is the fail-closed reading.
	if input.IsEnvelope && *forAddress != "" {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitUsageError,
			"--for applies to a single entry; given an envelope, sign the entries one at a time or drop --for"))
	}

	if input.IsEnvelope {
		signers := []soroauth.Signer{signer}
		if ext, ok := signer.(*execSigner); ok && ext.Address() == "" {
			entries, err := soroauth.EnvelopeEntries(input.Envelope)
			if err != nil {
				return writeJSONError(stdout, jsonMode, newErrorf(exitCodeForSigningError(err), "%w", err))
			}
			signers = nil
			seen := make(map[string]bool)
			for _, loc := range entries {
				addr, err := inferSingleEntryAddress(loc.Entry)
				if err != nil {
					return writeJSONError(stdout, jsonMode, err)
				}
				if addr != "" && !seen[addr] {
					seen[addr] = true
					signers = append(signers, ext.withAddress(addr))
				}
			}
		}

		signed, err := soroauth.AuthorizeEnvelope(context.Background(), input.Envelope,
			signers, expiration, passphrase)
		if err != nil {
			return writeJSONError(stdout, jsonMode, newErrorf(exitCodeForSigningError(err), "%w", err))
		}

		encoded, err := xdr.MarshalBase64(signed)
		if err != nil {
			return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "encoding the signed envelope: %w", err))
		}
		if jsonMode {
			enc := json.NewEncoder(stdout)
			enc.SetEscapeHTML(false)
			return enc.Encode(signOutput{SignedEnvelope: encoded})
		}
		fmt.Fprintln(stdout, encoded)
		return nil
	}

	if ext, ok := signer.(*execSigner); ok && ext.Address() == "" {
		addr, err := inferSingleEntryAddress(input.Entry)
		if err != nil {
			return writeJSONError(stdout, jsonMode, err)
		}
		signer = ext.withAddress(addr)
	}

	var opts []soroauth.AuthorizeOption
	if *forAddress != "" {
		opts = append(opts, soroauth.ForAddress(*forAddress))
	}

	signed, err := soroauth.AuthorizeEntry(context.Background(), input.Entry,
		signer, expiration, passphrase, opts...)
	if err != nil {
		return writeJSONError(stdout, jsonMode, newErrorf(exitCodeForSigningError(err), "%w", err))
	}

	encoded, err := encodeEntry(signed)
	if err != nil {
		return writeJSONError(stdout, jsonMode, newErrorf(ExitGeneralError, "%w", err))
	}

	if jsonMode {
		out := signOutput{SignedEntry: encoded}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintln(stdout, encoded)
	return nil
}

// resolveSigner turns the signer flags into a Signer. Exactly one of
// --secret-env (the name of an environment variable holding a seed, never the
// seed itself), --assertion, or --signer-cmd must be given; anything else is a
// usage error, including more than one at once, because precedence between two
// credentials would hide which one signed.
func resolveSigner(getenv func(string) string, secretEnv, assertion, signerCmd, forAddress string, signerTimeout time.Duration) (soroauth.Signer, error) {
	count := 0
	if secretEnv != "" {
		count++
	}
	if assertion != "" {
		count++
	}
	if signerCmd != "" {
		count++
	}
	if count != 1 {
		return nil, newErrorf(ExitUsageError, "--secret-env is required unless --assertion or --signer-cmd is given: exactly one of --secret-env or --assertion must be provided (or --signer-cmd)")
	}

	if signerCmd != "" {
		return newExecSigner(signerCmd, forAddress, signerTimeout, getenv)
	}

	if secretEnv == "" {
		// Passkey support not implemented in current library version.
		return nil, newErrorf(ExitUsageError, "passkey authentication is not yet supported")
	}

	full, err := resolveSeedKeypair(getenv, secretEnv)
	if err != nil {
		return nil, err
	}
	return soroauth.NewEd25519Signer(full), nil
}

// resolveSeedKeypair reads the seed named by secretEnv out of the environment
// and parses it, refusing anything that is not a secret seed.
//
// It is separate from resolveSigner because the submit subcommand needs the
// keypair itself — it signs the transaction envelope, which is a keypair's job
// and not a Signer's — and because keeping the three refusals in one place is
// what makes them say the same thing whichever subcommand hit them: an unset
// variable, a value that is not a Stellar key, and a public key offered where
// a secret seed belongs are three different mistakes with three different
// fixes, and the last one is the one a caller gets wrong by pasting the wrong
// half of a keypair.
func resolveSeedKeypair(getenv func(string) string, secretEnv string) (*keypair.Full, error) {
	seed := getenv(secretEnv)
	if seed == "" {
		return nil, newErrorf(ExitUsageError, "environment variable %s is empty or unset", secretEnv)
	}

	parsed, err := keypair.Parse(seed)
	if err != nil {
		return nil, newErrorf(ExitUsageError, "the value of %s is not a valid Stellar key", secretEnv)
	}
	full, ok := parsed.(*keypair.Full)
	if !ok {
		return nil, newErrorf(ExitUsageError, "the value of %s is a public key; a secret seed (S…) is required", secretEnv)
	}
	return full, nil
}

// runSignBatch signs every input in a batch file, or none of them.
//
// AuthorizeEntry runs per input rather than AuthorizeAll running once, so a
// failure names its 1-based line, but the externally visible rule is the
// library's all-or-nothing one: if ANY input fails, the encoded results are
// dropped unsent and the error carries the failure. A caller can therefore
// never mistake a partial batch for a complete one. Every input is attempted,
// so one run reports every line that needs fixing.
func runSignBatch(stdout io.Writer, entriesFlag string, stdin io.Reader, signer soroauth.Signer, expiration uint32, passphrase string, jsonFlag bool) error {
	inputs, err := readBatchEntries("--entries", entriesFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, jsonFlag, err)
	}
	if len(inputs) == 0 {
		return writeJSONError(stdout, jsonFlag, emptyBatchError("--entries", entriesFlag))
	}

	run := newBatchRun(len(inputs))
	encodedEntries := make([]string, 0, len(inputs))
	for _, in := range inputs {
		if in.Err != nil {
			run.fail(in.Index, in.Err)
			continue
		}

		entrySigner := signer
		if ext, ok := signer.(*execSigner); ok && ext.Address() == "" {
			addr, err := inferSingleEntryAddress(in.Entry)
			if err != nil {
				run.fail(in.Index, err)
				continue
			}
			entrySigner = ext.withAddress(addr)
		}

		signed, err := soroauth.AuthorizeEntry(context.Background(), in.Entry, entrySigner, expiration, passphrase)
		if err != nil {
			run.fail(in.Index, newErrorf(exitCodeForSigningError(err), "%w", err))
			continue
		}
		encoded, err := encodeEntry(signed)
		if err != nil {
			run.fail(in.Index, newErrorf(ExitGeneralError, "%w", err))
			continue
		}
		encodedEntries = append(encodedEntries, encoded)
	}

	if run.failed > 0 {
		// All-or-nothing: only the reasons are reported, no signed output.
		return writeJSONError(stdout, jsonFlag, run.signSummary())
	}

	for i, encoded := range encodedEntries {
		if jsonFlag {
			run.result(i+1, signOutput{SignedEntry: encoded})
		} else {
			fmt.Fprintf(stdout, "entry %d:\n%s\n", i+1, encoded)
		}
	}
	return run.finish(stdout, jsonFlag)
}

// exitCodeForSigningError maps a refusal or a verification failure onto the
// exit code that classifies it, so both the entry and the envelope paths report
// the same way.
func exitCodeForSigningError(err error) int {
	switch {
	case errors.Is(err, soroauth.ErrNoMatchingCredentialNode),
		errors.Is(err, soroauth.ErrAlreadySigned),
		errors.Is(err, soroauth.ErrSourceAccountCredentials),
		errors.Is(err, soroauth.ErrUnsupportedCredentials),
		errors.Is(err, soroauth.ErrDuplicateDelegate),
		errors.Is(err, soroauth.ErrMissingSigner),
		errors.Is(err, soroauth.ErrNoInvokeOperation),
		errors.Is(err, soroauth.ErrUnsupportedEnvelope),
		errors.Is(err, errExecSignerRefused):
		return ExitSigningRefusal
	case errors.Is(err, soroauth.ErrSignatureMismatch),
		errors.Is(err, soroauth.ErrInvalidExpiration),
		errors.Is(err, soroauth.ErrTooManySignatures):
		return ExitVerificationFailed
	default:
		return ExitGeneralError
	}
}
