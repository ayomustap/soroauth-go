package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const completionsUsage = `soroauth completions — emit a shell completion script.

usage:
  soroauth completions --shell bash|zsh|fish [--json]

Prints a completion script for the named shell on stdout. Source it or write it
to your shell's completion directory; README.md ("Shell completions") carries
the installation line for each shell:

  bash:  source <(soroauth completions --shell bash)          # interactive shells only
  bash:  soroauth completions --shell bash > /etc/bash_completion.d/soroauth
  zsh:   soroauth completions --shell zsh > "${fpath[1]}/_soroauth"
  fish:  soroauth completions --shell fish > ~/.config/fish/completions/soroauth.fish

bash, zsh, and fish complete subcommands, flags, enumerable flag values (the
three named networks — testnet, futurenet, public — while still permitting any
literal passphrase, plus every output format and shell name), and addresses
dynamically parsed from an --entry already present on the command line.
Dynamic address completion only parses base64 XDR in memory; it never executes
entry contents or runs a signer. --secret-env is completed by flag name only:
the shells never see or complete a variable's value.

With --json, prints a JSON object with fields "shell" and "script"; on error, a
JSON object with field "error" and exits non-zero.

exit codes:
  0  success
  2  usage error (missing or unknown --shell)
`

// dynamicCompletion identifies a dynamic value source for a flag in
// commandSpecs.
type dynamicCompletion string

const (
	dynamicNone           dynamicCompletion = ""
	dynamicEntryAddresses dynamicCompletion = "entry_addresses"
)

// Named networks suggested by shell completion for --network flags. Completion
// suggests these shorthands and never constrains a caller from typing a
// literal network passphrase.
var namedNetworks = []string{"testnet", "futurenet", "public"}

// flagSpec describes one flag of one subcommand, so the completion generators
// and the flag definitions in this package cannot drift apart silently. The
// per-command flag lists below are hand-maintained: TestSpecsMatchTheRealFlagSets
// in completions_test.go drives each subcommand's real flag parsing (through
// the same dispatcher main uses) and fails if the two lists disagree.
type flagSpec struct {
	Name        string            // long name, without the leading dashes
	Description string            // what the flag is for, shown by fish and zsh
	TakesValue  bool              // false for boolean flags
	Values      []string          // enumerable values to suggest on completion
	Dynamic     dynamicCompletion // dynamic value source, if any
}

// commandSpec describes one subcommand the completion scripts offer.
type commandSpec struct {
	Name        string
	Description string
	Flags       []flagSpec
}

// commandSpecs is the completion source of truth. Order is the order the
// shells print, which is the order of the usage text.
//
// The descriptions deliberately never embed a flag *value* that looks like a
// key: --secret-env names an environment variable holding a seed, and
// completions must suggest variable names, never values. No spec below carries
// anything secret, and the test suite asserts the generated scripts contain no
// seed- or address-shaped string.
var commandSpecs = []commandSpec{
	{
		Name:        "payload",
		Description: "print the signing preimage and payload hash for an entry",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "valid-until", Description: "the last ledger at which the signature is valid", TakesValue: true},
			{Name: "valid-for", Description: "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true, Values: namedNetworks},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "sign",
		Description: "sign an entry with a seed read from an environment variable",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "entries", Description: "a file of entries to sign, one base64 entry per line, or - for stdin", TakesValue: true},
			{Name: "valid-until", Description: "the last ledger at which the signature is valid", TakesValue: true},
			{Name: "valid-for", Description: "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true, Values: namedNetworks},
			{Name: "secret-env", Description: "name of the environment variable holding the seed", TakesValue: true},
			{Name: "assertion", Description: "path to a WebAuthn assertion JSON file, or - for stdin", TakesValue: true},
			{Name: "signer-cmd", Description: "path to an external signer executable speaking the remote protocol over stdin/stdout", TakesValue: true},
			{Name: "signer-timeout", Description: "timeout for the external signer executable", TakesValue: true},
			{Name: "for", Description: "credential node to sign, when it is not the signer's own address", TakesValue: true, Dynamic: dynamicEntryAddresses},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "simulate",
		Description: "run the record pass and print what the host recorded",
		Flags: []flagSpec{
			{Name: "entry", Description: "the transaction envelope to simulate, as base64 XDR", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint to simulate against (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "use-upgraded-auth", Description: "ask the host to record the address-bound V2 arm (best-effort)", TakesValue: false},
			{Name: "timeout", Description: "how long to wait for the simulation", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "submit",
		Description: "enforce, sign, send and poll a transaction",
		Flags: []flagSpec{
			{Name: "entry", Description: "the signed transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true},
			{Name: "secret-env", Description: "name of the environment variable holding the source account's seed", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint to submit to (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "allow-unsigned", Description: "submit even though an address entry is unsigned (the host will refuse it)", TakesValue: false},
			{Name: "timeout", Description: "how long to wait for the enforcing pass, the send and the poll", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "delegates",
		Description: "wrap an entry in a delegated-signer credential",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "the authorization entry, as base64 XDR", TakesValue: true},
			{Name: "valid-until", Description: "the last ledger at which the signatures are valid", TakesValue: true},
			{Name: "valid-for", Description: "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "delegate", Description: "a delegate address; repeat for several", TakesValue: true, Dynamic: dynamicEntryAddresses},
			{Name: "nested-json", Description: "JSON string defining nested delegate tree", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "inspect",
		Description: "print an entry's structure as JSON",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "the authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "entries", Description: "a file of entries to inspect, one base64 entry per line, or - for stdin", TakesValue: true},
			{Name: "json", Description: "accepted for consistency; inspect's output is always JSON", TakesValue: false},
		},
	},
	{
		Name:        "tree",
		Description: "render an entry's delegate tree as ASCII, DOT, or JSON",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "the authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "format", Description: "tree rendering: ascii or dot", TakesValue: true, Values: []string{"ascii", "dot"}},
			{Name: "json", Description: "output structured JSON instead of a rendering", TakesValue: false},
		},
	},
	{
		Name:        "tui",
		Description: "interactive TUI for inspecting and signing an entry",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "base64-encoded authorization entry (required)", TakesValue: true},
			{Name: "valid-until", Description: "signature expiration ledger (required)", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal passphrase (required)", TakesValue: true, Values: namedNetworks},
			{Name: "secret-env", Description: "name of environment variable holding the secret seed (required)", TakesValue: true},
			{Name: "for", Description: "target address to sign for (optional)", TakesValue: true, Dynamic: dynamicEntryAddresses},
		},
	},
	{
		Name:        "doctor",
		Description: "check the local environment for common first-run problems",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true, Values: namedNetworks},
			{Name: "rpc-url", Description: "URL to check network reachability against", TakesValue: true},
			{Name: "secret-env", Description: "name of an environment variable whose presence to check", TakesValue: true},
			{Name: "format", Description: "output format: text or json", TakesValue: true, Values: []string{"text", "json"}},
			{Name: "timeout", Description: "timeout for the network check", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "cross-compile",
		Description: "build soroauth for multiple targets",
		Flags: []flagSpec{
			{Name: "json", Description: "emit results as JSON (one object per line)", TakesValue: false},
			{Name: "targets", Description: "comma-separated GOOS/GOARCH pairs (default: all)", TakesValue: true},
			{Name: "output-dir", Description: "directory to write binaries (default: stdout only)", TakesValue: true},
		},
	},
	{
		Name:        "verify",
		Description: "check an entry's signatures without submitting it",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "entry", Description: "the authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "entries", Description: "a file of entries to verify, one base64 entry per line, or - for stdin", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true, Values: namedNetworks},
			{Name: "valid-until", Description: "assert the expiration the entry carries (optional)", TakesValue: true},
			{Name: "allow-unsigned", Description: "accept unsigned nodes (a Void top-level node of a delegates entry is legitimate under CAP-71-01)", TakesValue: false},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "diff",
		Description: "compare two entries and report what changed",
		Flags: []flagSpec{
			{Name: "config", Description: "path to CLI configuration file", TakesValue: true},
			{Name: "before", Description: "the first authorization entry, as base64 XDR", TakesValue: true},
			{Name: "after", Description: "the second authorization entry, as base64 XDR", TakesValue: true},
			{Name: "before-entries", Description: "a file of entries to compare, one base64 entry per line, or - for stdin; paired with --after-entries", TakesValue: true},
			{Name: "after-entries", Description: "a file of entries to compare, one base64 entry per line, or - for stdin; paired with --before-entries", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "completions",
		Description: "emit a shell completion script",
		Flags: []flagSpec{
			{Name: "shell", Description: "which shell: bash, zsh, or fish", TakesValue: true, Values: []string{"bash", "zsh", "fish"}},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "man",
		Description: "emit a roff man page",
		Flags: []flagSpec{
			{Name: "out", Description: "write the page to this path instead of stdout", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "wasm-budget",
		Description: "measure the wasm core against a size ceiling",
		Flags: []flagSpec{
			{Name: "out", Description: "path to the wasm artifact to measure", TakesValue: true},
			{Name: "budget", Description: "maximum allowed size in bytes", TakesValue: true},
			{Name: "prev-size", Description: "previous release's size, for a delta", TakesValue: true},
			{Name: "build-cmd", Description: "command to build the artifact before measuring", TakesValue: true},
			{Name: "json", Description: "output the result as JSON", TakesValue: false},
		},
	},
}

// completionsOutput is the shape of the --json success object.
type completionsOutput struct {
	Shell  string `json:"shell"`
	Script string `json:"script"`
}

func runCompletions(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("completions", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, completionsUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	shellFlag := flags.String("shell", "", "which shell to generate completions for: bash, zsh, or fish")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}
	if *shellFlag == "" {
		return writeJSONError(stdout, *jsonFlag,
			newErrorf(ExitUsageError, "--shell is required: one of bash, zsh, or fish"))
	}

	var script string
	switch *shellFlag {
	case "bash":
		script = bashCompletionScript()
	case "zsh":
		script = zshCompletionScript()
	case "fish":
		script = fishCompletionScript()
	default:
		return writeJSONError(stdout, *jsonFlag,
			newErrorf(ExitUsageError, "unknown shell %q: expected bash, zsh, or fish", *shellFlag))
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(completionsOutput{Shell: *shellFlag, Script: script})
	}

	fmt.Fprint(stdout, script)
	return nil
}

// runCompleteAddresses implements the hidden "__complete-addresses" helper
// invoked by the generated bash, zsh, and fish completion scripts when
// completing --for or --delegate.
//
// Security invariant: Dynamic completion is a parsing-only operation. This
// function decodes the base64 XDR passed via --entry in memory using the
// library's bounded XDR decoders and prints the credential node addresses it
// finds, one per line. It never executes the entry's contents, never spawns a
// subprocess, never reads a secret environment variable, and never invokes a
// signer. Malformed or missing input quietly produces no output and exits 0 so
// pressing Tab on an incomplete command line never prints an error to the
// user's terminal.
func runCompleteAddresses(args []string, stdout io.Writer) error {
	var entryVal string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--entry" && i+1 < len(args) {
			entryVal = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--entry=") {
			entryVal = strings.TrimPrefix(arg, "--entry=")
		}
	}
	entryVal = strings.TrimSpace(entryVal)
	if entryVal == "" || entryVal == "-" {
		return nil
	}

	for _, addr := range extractEntryAddresses(entryVal) {
		fmt.Fprintln(stdout, addr)
	}
	return nil
}

// extractEntryAddresses parses a base64-encoded SorobanAuthorizationEntry or
// TransactionEnvelope and returns all unique credential addresses (top-level
// and delegates at every depth) in traversal order.
//
// It performs pure XDR deserialization and never executes anything or touches
// the network or filesystem.
func extractEntryAddresses(entryB64 string) []string {
	var seen = make(map[string]bool)
	var out []string
	add := func(addr string) {
		if addr != "" && !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	var walkDelegates func(delegates []soroauth.NodeInfo)
	walkDelegates = func(delegates []soroauth.NodeInfo) {
		for _, d := range delegates {
			add(d.Address)
			walkDelegates(d.Nested)
		}
	}

	if entry, err := soroauth.DecodeAuthorizationEntry(entryB64); err == nil {
		if info, err := soroauth.Inspect(entry); err == nil {
			add(info.Address)
			walkDelegates(info.Delegates)
			return out
		}
	}

	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(entryB64, &envelope); err == nil {
		if infos, err := soroauth.InspectEnvelope(envelope); err == nil {
			for _, item := range infos {
				add(item.Address)
				walkDelegates(item.Delegates)
			}
		}
	}
	return out
}

// bashCompletionScript renders the bash completion. It is a plain function,
// not a template: the completed words, enumerable flag values, and dynamic
// address hooks come from commandSpecs at generation time, so the emitted
// script never drifts from the spec table.
func bashCompletionScript() string {
	var b strings.Builder
	b.WriteString("# bash completion for soroauth\n")
	b.WriteString("# generated by: soroauth completions --shell bash\n")
	b.WriteString("# sourcing this file defines the completion function; see README.md for installation\n\n")
	b.WriteString("_soroauth_entry_addresses()\n{\n")
	b.WriteString("\tlocal i entry=\"\"\n")
	b.WriteString("\tfor (( i=1; i < ${#COMP_WORDS[@]}; i++ )); do\n")
	b.WriteString("\t\tif [[ \"${COMP_WORDS[i]}\" == \"--entry\" ]] && (( i + 1 < ${#COMP_WORDS[@]} )); then\n")
	b.WriteString("\t\t\tentry=\"${COMP_WORDS[i+1]}\"\n")
	b.WriteString("\t\t\tbreak\n")
	b.WriteString("\t\telif [[ \"${COMP_WORDS[i]}\" == --entry=* ]]; then\n")
	b.WriteString("\t\t\tentry=\"${COMP_WORDS[i]#--entry=}\"\n")
	b.WriteString("\t\t\tbreak\n")
	b.WriteString("\t\tfi\n")
	b.WriteString("\tdone\n")
	b.WriteString("\tif [[ -n \"$entry\" && \"$entry\" != \"-\" ]]; then\n")
	b.WriteString("\t\t\"${COMP_WORDS[0]}\" __complete-addresses --entry \"$entry\" 2>/dev/null\n")
	b.WriteString("\tfi\n")
	b.WriteString("}\n\n")
	b.WriteString("_soroauth_completions()\n{\n")
	b.WriteString("\tlocal cur prev cmd\n")
	b.WriteString("\tcur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	b.WriteString("\tprev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n")
	b.WriteString("\tcmd=\"\"\n")
	b.WriteString("\tif (( COMP_CWORD > 1 )); then\n")
	b.WriteString("\t\tcmd=\"${COMP_WORDS[1]}\"\n")
	b.WriteString("\tfi\n\n")

	b.WriteString("\t# complete a subcommand-specific enumerable or dynamic flag value\n")
	b.WriteString("\tcase \"$cmd:$prev\" in\n")
	for _, cmd := range commandSpecs {
		for _, f := range cmd.Flags {
			if len(f.Values) > 0 {
				b.WriteString(fmt.Sprintf("\t\t%s:--%s)\n", cmd.Name, f.Name))
				b.WriteString(fmt.Sprintf("\t\t\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(f.Values, " ")))
				b.WriteString("\t\t\treturn 0\n\t\t\t;;\n")
			} else if f.Dynamic == dynamicEntryAddresses {
				b.WriteString(fmt.Sprintf("\t\t%s:--%s)\n", cmd.Name, f.Name))
				b.WriteString("\t\t\tlocal addrs\n")
				b.WriteString("\t\t\taddrs=\"$(_soroauth_entry_addresses)\"\n")
				b.WriteString("\t\t\tCOMPREPLY=( $(compgen -W \"$addrs\" -- \"$cur\") )\n")
				b.WriteString("\t\t\treturn 0\n\t\t\t;;\n")
			}
		}
	}
	b.WriteString("\tesac\n")

	// Also emit position-independent fallbacks derived from commandSpecs so
	// completing a value flag when the subcommand is not at index 1 still works.
	b.WriteString("\n\t# complete an enumerable or dynamic flag's value at any position\n")
	b.WriteString("\tcase \"$prev\" in\n")
	for _, agg := range aggregateValueFlags() {
		b.WriteString(fmt.Sprintf("\t\t--%s)\n", agg.Name))
		if agg.Dynamic == dynamicEntryAddresses {
			b.WriteString("\t\t\tlocal addrs\n")
			b.WriteString("\t\t\taddrs=\"$(_soroauth_entry_addresses)\"\n")
			b.WriteString("\t\t\tCOMPREPLY=( $(compgen -W \"$addrs\" -- \"$cur\") )\n")
		} else {
			b.WriteString(fmt.Sprintf("\t\t\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(agg.Values, " ")))
		}
		b.WriteString("\t\t\treturn 0\n\t\t\t;;\n")
	}
	b.WriteString("\tesac\n")

	b.WriteString("\n\t# after a subcommand, complete that subcommand's flags\n")
	b.WriteString("\tif (( COMP_CWORD > 1 )); then\n")
	b.WriteString("\t\tcase \"$cmd\" in\n")
	for _, cmd := range commandSpecs {
		words := make([]string, 0, len(cmd.Flags)+2)
		words = append(words, "-h", "--help")
		for _, f := range cmd.Flags {
			words = append(words, "--"+f.Name)
		}
		b.WriteString(fmt.Sprintf("\t\t\t%s)\n", cmd.Name))
		b.WriteString(fmt.Sprintf("\t\t\t\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(words, " ")))
		b.WriteString("\t\t\t\treturn 0\n\t\t\t\t;;\n")
	}
	b.WriteString("\t\tesac\n")
	b.WriteString("\tfi\n\n")
	b.WriteString("\t# first word: the subcommands\n")
	b.WriteString(fmt.Sprintf("\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(commandNames(), " ")))
	b.WriteString("}\n\n")
	b.WriteString("complete -F _soroauth_completions soroauth\n")
	return b.String()
}

// aggregateValueFlags collects the union of enumerable and dynamic flags across
// commandSpecs in spec order, for bash's position-independent fallback case.
func aggregateValueFlags() []flagSpec {
	var order []string
	byName := make(map[string]*flagSpec)
	for _, cmd := range commandSpecs {
		for _, f := range cmd.Flags {
			if len(f.Values) == 0 && f.Dynamic == dynamicNone {
				continue
			}
			existing, ok := byName[f.Name]
			if !ok {
				cp := flagSpec{
					Name:    f.Name,
					Dynamic: f.Dynamic,
					Values:  append([]string(nil), f.Values...),
				}
				byName[f.Name] = &cp
				order = append(order, f.Name)
				continue
			}
			for _, v := range f.Values {
				found := false
				for _, ev := range existing.Values {
					if ev == v {
						found = true
						break
					}
				}
				if !found {
					existing.Values = append(existing.Values, v)
				}
			}
		}
	}
	out := make([]flagSpec, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// zshCompletionScript renders the zsh completion with the shell's native
// _arguments machinery, so value-taking flags complete with descriptions and
// enumerable or dynamic values, and boolean flags complete bare. Every
// user-visible string goes through zshQuote as a whole unit, because an
// apostrophe in a description (signer's, inspect's) ends a single-quoted zsh
// string unless escaped.
func zshCompletionScript() string {
	var b strings.Builder
	b.WriteString("#compdef soroauth\n")
	b.WriteString("# generated by: soroauth completions --shell zsh\n")
	b.WriteString("# install to a directory in $fpath as _soroauth; see README.md\n\n")
	b.WriteString("_soroauth_entry_addresses()\n{\n")
	b.WriteString("\tlocal i entry=\"\"\n")
	b.WriteString("\tfor (( i=1; i <= $#words; i++ )); do\n")
	b.WriteString("\t\tif [[ \"${words[i]}\" == \"--entry\" ]] && (( i + 1 <= $#words )); then\n")
	b.WriteString("\t\t\tentry=\"${words[i+1]}\"\n")
	b.WriteString("\t\t\tbreak\n")
	b.WriteString("\t\telif [[ \"${words[i]}\" == --entry=* ]]; then\n")
	b.WriteString("\t\t\tentry=\"${words[i]#--entry=}\"\n")
	b.WriteString("\t\t\tbreak\n")
	b.WriteString("\t\tfi\n")
	b.WriteString("\tdone\n")
	b.WriteString("\tif [[ -n \"$entry\" && \"$entry\" != \"-\" ]]; then\n")
	b.WriteString("\t\tlocal -a addrs\n")
	b.WriteString("\t\taddrs=( ${(f)\"$(\"${words[1]}\" __complete-addresses --entry \"$entry\" 2>/dev/null)\"} )\n")
	b.WriteString("\t\t(( $#addrs > 0 )) && _describe 'address' addrs\n")
	b.WriteString("\tfi\n")
	b.WriteString("}\n\n")
	b.WriteString("_soroauth()\n{\n")
	b.WriteString("\tlocal -a cmds\n")
	b.WriteString("\tcmds=(\n")
	for _, cmd := range commandSpecs {
		b.WriteString("\t\t" + zshQuote(cmd.Name+":"+cmd.Description) + "\n")
	}
	b.WriteString("\t)\n")
	b.WriteString("\tif (( CURRENT == 2 )); then\n")
	b.WriteString("\t\t_describe 'command' cmds\n")
	b.WriteString("\telse\n")
	b.WriteString("\t\tlocal cmd=\"${words[2]}\"\n")
	b.WriteString("\t\tcase \"$cmd\" in\n")
	for _, cmd := range commandSpecs {
		b.WriteString(fmt.Sprintf("\t\t\t(%s)\n", cmd.Name))
		b.WriteString("\t\t\t_arguments \\\n")
		parts := make([]string, 0, len(cmd.Flags)+1)
		// The closing quote of the help spec is part of this string: the join
		// separator (" \\") lands outside every part's quotes, and an unclosed
		// quote here shifts every quote after it to end of file.
		parts = append(parts, `'(-h --help)'{-h,--help}'[show this help]'`)
		for _, f := range cmd.Flags {
			switch {
			case f.Dynamic == dynamicEntryAddresses:
				parts = append(parts, zshQuote(fmt.Sprintf("--%s=[%s]:%s:_soroauth_entry_addresses", f.Name, f.Description, f.Name)))
			case len(f.Values) > 0:
				parts = append(parts, zshQuote(fmt.Sprintf("--%s=[%s]:%s:(%s)", f.Name, f.Description, f.Name, strings.Join(f.Values, " "))))
			case f.TakesValue:
				parts = append(parts, zshQuote(fmt.Sprintf("--%s=[%s]", f.Name, f.Description)))
			default:
				parts = append(parts, zshQuote(fmt.Sprintf("--%s[%s]", f.Name, f.Description)))
			}
		}
		b.WriteString("\t\t\t\t" + strings.Join(parts, " \\\n\t\t\t\t") + "\n")
		b.WriteString("\t\t\t\t;;\n")
	}
	b.WriteString("\t\tesac\n")
	b.WriteString("\tfi\n")
	b.WriteString("}\n\n")
	b.WriteString("compdef _soroauth soroauth\n")
	return b.String()
}

// fishCompletionScript renders the fish completion. Fish reads its
// completions eagerly, one `complete` line per word, and is the one shell
// whose completions carry descriptions natively, so the specs' descriptions
// appear in the user's tab menu. Each description goes through fishQuote as
// a whole unit for the same apostrophe reason as zsh.
func fishCompletionScript() string {
	var b strings.Builder
	b.WriteString("# fish completion for soroauth\n")
	b.WriteString("# generated by: soroauth completions --shell fish\n")
	b.WriteString("# install to ~/.config/fish/completions/soroauth.fish; see README.md\n\n")
	b.WriteString("function __soroauth_entry_addresses\n")
	b.WriteString("\tset -l tokens (commandline -opc)\n")
	b.WriteString("\tset -l entry \"\"\n")
	b.WriteString("\tset -l count (count $tokens)\n")
	b.WriteString("\tfor i in (seq 1 $count)\n")
	b.WriteString("\t\tif test \"$tokens[$i]\" = \"--entry\"\n")
	b.WriteString("\t\t\tset -l next (math $i + 1)\n")
	b.WriteString("\t\t\tif test $next -le $count\n")
	b.WriteString("\t\t\t\tset entry \"$tokens[$next]\"\n")
	b.WriteString("\t\t\t\tbreak\n")
	b.WriteString("\t\t\tend\n")
	b.WriteString("\t\telse if string match -q -- '--entry=*' \"$tokens[$i]\"\n")
	b.WriteString("\t\t\tset entry (string replace -- '--entry=' '' \"$tokens[$i]\")\n")
	b.WriteString("\t\t\tbreak\n")
	b.WriteString("\t\tend\n")
	b.WriteString("\tend\n")
	b.WriteString("\tif test -n \"$entry\" -a \"$entry\" != \"-\"\n")
	b.WriteString("\t\t\"$tokens[1]\" __complete-addresses --entry \"$entry\" 2>/dev/null\n")
	b.WriteString("\tend\n")
	b.WriteString("end\n\n")
	for _, cmd := range commandSpecs {
		b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_use_subcommand' -a %s -d %s\n",
			fishQuote(cmd.Name), fishQuote(cmd.Description)))
	}
	b.WriteString("\n")
	for _, cmd := range commandSpecs {
		for _, f := range cmd.Flags {
			switch {
			case f.Dynamic == dynamicEntryAddresses:
				b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_seen_subcommand_from %s' -l %s -r -f -a '(__soroauth_entry_addresses)' -d %s\n",
					cmd.Name, f.Name, fishQuote(f.Description)))
			case len(f.Values) > 0:
				b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_seen_subcommand_from %s' -l %s -r -f -a %s -d %s\n",
					cmd.Name, f.Name, fishQuote(strings.Join(f.Values, " ")), fishQuote(f.Description)))
			default:
				b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_seen_subcommand_from %s' -l %s -d %s\n",
					cmd.Name, f.Name, fishQuote(f.Description)))
			}
		}
		// A subcommand's own -h/--help, offered alongside its flags.
		b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_seen_subcommand_from %s' -s h -l help -d %s\n",
			cmd.Name, fishQuote("show this help")))
	}
	return b.String()
}

// commandNames returns the subcommand names in spec order, plus "help", which
// the dispatcher accepts but the spec table does not carry (it has no flags
// of its own).
func commandNames() []string {
	names := make([]string, 0, len(commandSpecs)+1)
	for _, cmd := range commandSpecs {
		names = append(names, cmd.Name)
	}
	return append(names, "help")
}

// zshQuote renders s as a single-quoted zsh string, escaping any embedded
// apostrophe with the close-escape-reopen convention, which zsh shares with
// POSIX shell.
func zshQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote renders s as a single-quoted fish string. Fish — unlike the
// POSIX shells — treats a backslash before an apostrophe INSIDE single quotes
// as an escape, so '...' quoting with \' is the one correct form; the POSIX
// close-escape-reopen trick ( '\” ) reads as an unbalanced quote in fish and
// aborts the load of the whole completion file at that line.
func fishQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}
