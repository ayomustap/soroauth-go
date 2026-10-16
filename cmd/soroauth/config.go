package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
)

// Source labels reported by "soroauth doctor" to show where each resolved
// configuration value came from.
const (
	sourceFlag    = "flag"
	sourceEnv     = "env"
	sourceFile    = "file"
	sourceDefault = "default"
)

// Environment variable names for the CLI configuration precedence chain:
// flag, then environment, then config file, then built-in default.
const (
	envConfig    = "SOROAUTH_CONFIG"
	envNetwork   = "SOROAUTH_NETWORK"
	envRPCURL    = "SOROAUTH_RPC_URL"
	envSecretEnv = "SOROAUTH_SECRET_ENV"
	envFormat    = "SOROAUTH_FORMAT"
)

// maxConfigBytes bounds the size of a configuration file the CLI will read.
const maxConfigBytes = 64 << 10

// fileConfig is the on-disk JSON schema for the CLI configuration file.
//
// No secret value may ever be stored here: SecretEnv names an environment
// variable holding a seed, never the seed itself.
type fileConfig struct {
	Network   string `json:"network"`
	RPCURL    string `json:"rpc_url"`
	SecretEnv string `json:"secret_env"`
	Format    string `json:"format"`
}

// loadedConfig holds the parsed configuration file together with the path it
// was loaded from and whether the file existed on disk.
type loadedConfig struct {
	Path   string
	Loaded bool
	File   fileConfig
}

// resolvedValue pairs an effective configuration value with the precedence
// layer ("flag", "env", "file", or "default") that supplied it.
type resolvedValue struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// doctorConfigReport is the configuration section of "soroauth doctor": which
// file was loaded (empty when none was loaded) and where each setting's value
// came from.
type doctorConfigReport struct {
	File      string        `json:"file"`
	Loaded    bool          `json:"loaded"`
	Network   resolvedValue `json:"network"`
	RPCURL    resolvedValue `json:"rpc_url"`
	SecretEnv resolvedValue `json:"secret_env"`
	Format    resolvedValue `json:"format"`
}

var (
	envVarNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	base32SeedLike    = regexp.MustCompile(`^S[A-Z2-7]{9,}$`)
	strkey56Pattern   = regexp.MustCompile(`^[SGC][A-Z2-7]{55}$`)
)

// forbiddenSecretKeys lists JSON keys whose presence in a config file means the
// caller tried to store a raw secret rather than an environment variable name.
var forbiddenSecretKeys = map[string]bool{
	"secret":      true,
	"seed":        true,
	"private_key": true,
	"secret_key":  true,
	"signing_key": true,
	"key":         true,
}

// resolveConfigPath determines which configuration file path to inspect,
// following the order: --config flag, $SOROAUTH_CONFIG,
// $XDG_CONFIG_HOME/soroauth/config.json, $HOME/.config/soroauth/config.json.
//
// All environment lookups go through getenv rather than os.Getenv directly so
// tests with an injected environment stay isolated from the host user's home
// directory.
func resolveConfigPath(flagPath string, getenv func(string) string) string {
	if flagPath != "" {
		return flagPath
	}
	if envPath := getenv(envConfig); envPath != "" {
		return envPath
	}
	if xdg := getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "soroauth", "config.json")
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "soroauth", "config.json")
	}
	return ""
}

// looksLikeSecret reports whether value has the shape of a cryptographic secret
// or key rather than an environment variable name.
//
// This catches:
//   - any valid Stellar strkey (S… seed, G… account, C… contract, M… muxed)
//   - any 56-character strkey-shaped S…, G…, or C… string (even with a bad checksum)
//   - any uppercase base32 string starting with 'S' of length >= 10 without
//     underscores (such as test seeds like SABCDEXAMPLE or SNOTAREALSEEDATALL)
//   - any 64-character hex string (a 32-byte raw ed25519 seed)
//   - any PEM-encoded block ("-----BEGIN")
func looksLikeSecret(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "-----BEGIN") {
		return true
	}
	if _, err := keypair.Parse(trimmed); err == nil {
		return true
	}
	if _, _, err := strkey.DecodeAny(trimmed); err == nil {
		return true
	}
	if strkey56Pattern.MatchString(trimmed) {
		return true
	}
	if base32SeedLike.MatchString(trimmed) {
		return true
	}
	if len(trimmed) == 64 {
		if _, err := hex.DecodeString(trimmed); err == nil {
			return true
		}
	}
	return false
}

// loadConfig reads and validates the CLI configuration file.
//
// A missing file is not an error: it returns Loaded=false and an empty
// fileConfig. An unreadable or unparseable file, an unknown field, an invalid
// format, or any secret-shaped value is an ExitUsageError. Secret-shaped
// values are never echoed into the returned error.
func loadConfig(flagPath string, getenv func(string) string) (loadedConfig, error) {
	path := resolveConfigPath(flagPath, getenv)
	if path == "" {
		return loadedConfig{}, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return loadedConfig{}, nil
		}
		return loadedConfig{}, newErrorf(ExitUsageError, "reading config file %s: %w", path, err)
	}
	if len(raw) > maxConfigBytes {
		return loadedConfig{}, newErrorf(ExitUsageError, "config file %s exceeds maximum size (%d bytes)", path, maxConfigBytes)
	}

	// First check top-level keys so a forbidden key like "seed" or "secret" gets
	// an explicit security refusal rather than a generic unknown-field message,
	// without ever echoing any secret value in the file.
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err == nil {
		for k, v := range rawMap {
			if forbiddenSecretKeys[strings.ToLower(k)] {
				return loadedConfig{}, newErrorf(ExitUsageError,
					"config file %s: key %q is refused; no secret value may be stored in the config file (use \"secret_env\" to name an environment variable)",
					path, k)
			}
			var strVal string
			if json.Unmarshal(v, &strVal) == nil && looksLikeSecret(strVal) {
				return loadedConfig{}, newErrorf(ExitUsageError,
					"config file %s: field %q contains a secret-shaped value; no secret value may be stored in the config file (only the name of an environment variable in \"secret_env\")",
					path, k)
			}
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var cfg fileConfig
	if err := decoder.Decode(&cfg); err != nil {
		return loadedConfig{}, newErrorf(ExitUsageError, "parsing config file %s: %w", path, err)
	}
	// Ensure there is no trailing content after the root JSON object.
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return loadedConfig{}, newErrorf(ExitUsageError, "parsing config file %s: unexpected trailing content after JSON object", path)
	}

	if cfg.SecretEnv != "" {
		if looksLikeSecret(cfg.SecretEnv) {
			return loadedConfig{}, newErrorf(ExitUsageError,
				"config file %s: secret_env contains a secret-shaped value; store the secret in an environment variable and put only its variable name in secret_env",
				path)
		}
		if !envVarNamePattern.MatchString(cfg.SecretEnv) {
			return loadedConfig{}, newErrorf(ExitUsageError,
				"config file %s: secret_env must be a valid environment variable name (letters, digits, and underscores), never a secret value",
				path)
		}
	}

	if cfg.Format != "" {
		switch cfg.Format {
		case "text", "json", "ascii", "dot":
		default:
			return loadedConfig{}, newErrorf(ExitUsageError,
				"config file %s: invalid format %q (expected text, json, ascii, or dot)",
				path, cfg.Format)
		}
	}

	return loadedConfig{
		Path:   path,
		Loaded: true,
		File:   cfg,
	}, nil
}

// visitedFlags returns the set of flag names explicitly provided on the
// command line in fs.
func visitedFlags(fs *flag.FlagSet) map[string]bool {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		set[f.Name] = true
	})
	return set
}

// resolvePrecedence resolves a single string setting using the documented
// four-level precedence order:
//  1. command-line flag (when flagSet is true or flagVal != "" for unvisited callers)
//  2. environment variable (envVar via getenv)
//  3. configuration file (fileVal when cfg.Loaded is true)
//  4. built-in default (defaultVal)
func resolvePrecedence(flagSet bool, flagVal, envVar string, getenv func(string) string, cfg loadedConfig, fileVal, defaultVal string) resolvedValue {
	if flagSet {
		return resolvedValue{Value: flagVal, Source: sourceFlag}
	}
	if getenv != nil {
		if envVal := getenv(envVar); envVal != "" {
			return resolvedValue{Value: envVal, Source: sourceEnv}
		}
	}
	if cfg.Loaded && fileVal != "" {
		return resolvedValue{Value: fileVal, Source: sourceFile}
	}
	return resolvedValue{Value: defaultVal, Source: sourceDefault}
}

func flagIsSet(set map[string]bool, name, flagVal string) bool {
	if set != nil {
		return set[name]
	}
	return flagVal != ""
}

// resolveNetworkValue resolves the network setting across flag, environment,
// config file, and built-in default.
func resolveNetworkValue(set map[string]bool, flagVal string, getenv func(string) string, cfg loadedConfig) resolvedValue {
	return resolvePrecedence(flagIsSet(set, "network", flagVal), flagVal, envNetwork, getenv, cfg, cfg.File.Network, "")
}

// resolveRPCURLValue resolves the RPC URL setting across flag, environment,
// config file, and built-in default.
func resolveRPCURLValue(set map[string]bool, flagVal string, getenv func(string) string, cfg loadedConfig, defaultURL string) resolvedValue {
	return resolvePrecedence(flagIsSet(set, "rpc-url", flagVal), flagVal, envRPCURL, getenv, cfg, cfg.File.RPCURL, defaultURL)
}

// resolveSecretEnvValue resolves the secret environment variable name across
// flag, environment, config file, and built-in default.
func resolveSecretEnvValue(set map[string]bool, flagVal string, getenv func(string) string, cfg loadedConfig) resolvedValue {
	return resolvePrecedence(flagIsSet(set, "secret-env", flagVal), flagVal, envSecretEnv, getenv, cfg, cfg.File.SecretEnv, "")
}

// resolveFormatValue resolves the output format across --json / --format flags,
// $SOROAUTH_FORMAT, the config file's "format" field, and defaultFormat.
func resolveFormatValue(set map[string]bool, formatFlagVal string, jsonFlagVal bool, getenv func(string) string, cfg loadedConfig, defaultFormat string) (resolvedValue, error) {
	if set != nil && set["json"] {
		if jsonFlagVal {
			return resolvedValue{Value: "json", Source: sourceFlag}, nil
		}
		if set["format"] {
			return resolvedValue{Value: formatFlagVal, Source: sourceFlag}, nil
		}
		return resolvedValue{Value: defaultFormat, Source: sourceFlag}, nil
	}
	if flagIsSet(set, "format", formatFlagVal) {
		return resolvedValue{Value: formatFlagVal, Source: sourceFlag}, nil
	}
	if jsonFlagVal {
		return resolvedValue{Value: "json", Source: sourceFlag}, nil
	}
	if getenv != nil {
		if envVal := getenv(envFormat); envVal != "" {
			switch envVal {
			case "text", "json", "ascii", "dot":
				return resolvedValue{Value: envVal, Source: sourceEnv}, nil
			default:
				return resolvedValue{}, newErrorf(ExitUsageError,
					"invalid %s %q (expected text, json, ascii, or dot)", envFormat, envVal)
			}
		}
	}
	if cfg.Loaded && cfg.File.Format != "" {
		return resolvedValue{Value: cfg.File.Format, Source: sourceFile}, nil
	}
	return resolvedValue{Value: defaultFormat, Source: sourceDefault}, nil
}

// resolveJSONMode resolves whether a subcommand should emit JSON output,
// honouring --json, $SOROAUTH_FORMAT, and the config file's "format" field.
func resolveJSONMode(set map[string]bool, jsonFlagVal bool, getenv func(string) string, cfg loadedConfig) (bool, error) {
	res, err := resolveFormatValue(set, "", jsonFlagVal, getenv, cfg, "text")
	if err != nil {
		return jsonFlagVal, err
	}
	return res.Value == "json", nil
}
