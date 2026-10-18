package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	return path
}

// TestConfigPrecedenceOrder verifies the documented 4-layer precedence chain:
// command-line flag, then environment variable, then config file, then built-in default.
func TestConfigPrecedenceOrder(t *testing.T) {
	srvFile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvFile.Close()

	srvEnv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvEnv.Close()

	srvFlag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvFlag.Close()

	cfgPath := writeTempConfig(t, `{
  "network": "futurenet",
  "rpc_url": "`+srvFile.URL+`",
  "secret_env": "FILE_SEED_VAR",
  "format": "json"
}`)

	t.Run("default layer when nothing is configured", func(t *testing.T) {
		stdout, _, err := runCLIEnv(t, map[string]string{},
			"doctor", "--rpc-url", srvFlag.URL, "--json")
		if err != nil {
			t.Fatalf("doctor failed: %v", err)
		}
		var report doctorReport
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("unmarshaling doctor report: %v", err)
		}
		if report.Config.Loaded {
			t.Errorf("expected Config.Loaded = false, got true (file: %q)", report.Config.File)
		}
		if report.Config.Network.Source != sourceDefault || report.Config.Network.Value != "" {
			t.Errorf("network = %+v, want empty from default", report.Config.Network)
		}
		if report.Config.SecretEnv.Source != sourceDefault || report.Config.SecretEnv.Value != "" {
			t.Errorf("secret_env = %+v, want empty from default", report.Config.SecretEnv)
		}
		if report.Config.RPCURL.Source != sourceFlag || report.Config.RPCURL.Value != srvFlag.URL {
			t.Errorf("rpc_url = %+v, want %q from flag", report.Config.RPCURL, srvFlag.URL)
		}
	})

	t.Run("file overrides built-in default", func(t *testing.T) {
		stdout, _, err := runCLIEnv(t, map[string]string{
			"FILE_SEED_VAR": doctorTestKey(t, "soroauth-config-test").Seed(),
		}, "doctor", "--config", cfgPath)
		if err != nil {
			t.Fatalf("doctor with config file failed: %v", err)
		}
		// format in file is "json", so stdout must be valid JSON even without --json
		var report doctorReport
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("expected JSON output from file format=json, got error: %v\nstdout: %s", err, stdout)
		}
		if !report.Config.Loaded || report.Config.File != cfgPath {
			t.Errorf("config file report = %+v, want Loaded=true File=%q", report.Config, cfgPath)
		}
		if report.Config.Network != (resolvedValue{Value: "futurenet", Source: sourceFile}) {
			t.Errorf("network = %+v, want futurenet from file", report.Config.Network)
		}
		if report.Config.RPCURL != (resolvedValue{Value: srvFile.URL, Source: sourceFile}) {
			t.Errorf("rpc_url = %+v, want %s from file", report.Config.RPCURL, srvFile.URL)
		}
		if report.Config.SecretEnv != (resolvedValue{Value: "FILE_SEED_VAR", Source: sourceFile}) {
			t.Errorf("secret_env = %+v, want FILE_SEED_VAR from file", report.Config.SecretEnv)
		}
		if report.Config.Format != (resolvedValue{Value: "json", Source: sourceFile}) {
			t.Errorf("format = %+v, want json from file", report.Config.Format)
		}
	})

	t.Run("environment overrides file", func(t *testing.T) {
		stdout, _, err := runCLIEnv(t, map[string]string{
			envConfig:      cfgPath,
			envNetwork:     "public",
			envRPCURL:      srvEnv.URL,
			envSecretEnv:   "ENV_SEED_VAR",
			envFormat:      "text",
			"ENV_SEED_VAR": doctorTestKey(t, "soroauth-config-test").Seed(),
		}, "doctor")
		if err != nil {
			t.Fatalf("doctor failed: %v", err)
		}
		for _, want := range []string{
			"config file:     " + cfgPath + " (loaded)",
			"network:         public (source: env)",
			"rpc-url:         " + srvEnv.URL + " (source: env)",
			"secret-env:      ENV_SEED_VAR (source: env)",
			"format:          text (source: env)",
			"all checks passed",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("human-readable doctor output missing %q\ngot:\n%s", want, stdout)
			}
		}
	})

	t.Run("flag overrides environment and file", func(t *testing.T) {
		stdout, _, err := runCLIEnv(t, map[string]string{
			envConfig:       cfgPath,
			envNetwork:      "public",
			envRPCURL:       srvEnv.URL,
			envSecretEnv:    "ENV_SEED_VAR",
			envFormat:       "text",
			"FLAG_SEED_VAR": doctorTestKey(t, "soroauth-config-test").Seed(),
		}, "doctor",
			"--network", "testnet",
			"--rpc-url", srvFlag.URL,
			"--secret-env", "FLAG_SEED_VAR",
			"--json")
		if err != nil {
			t.Fatalf("doctor failed: %v", err)
		}
		var report doctorReport
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("unmarshaling doctor report: %v", err)
		}
		if report.Config.Network != (resolvedValue{Value: "testnet", Source: sourceFlag}) {
			t.Errorf("network = %+v, want testnet from flag", report.Config.Network)
		}
		if report.Config.RPCURL != (resolvedValue{Value: srvFlag.URL, Source: sourceFlag}) {
			t.Errorf("rpc_url = %+v, want %s from flag", report.Config.RPCURL, srvFlag.URL)
		}
		if report.Config.SecretEnv != (resolvedValue{Value: "FLAG_SEED_VAR", Source: sourceFlag}) {
			t.Errorf("secret_env = %+v, want FLAG_SEED_VAR from flag", report.Config.SecretEnv)
		}
		if report.Config.Format != (resolvedValue{Value: "json", Source: sourceFlag}) {
			t.Errorf("format = %+v, want json from flag", report.Config.Format)
		}
	})

	t.Run("sign and verify use config file defaults and XDG_CONFIG_HOME discovery", func(t *testing.T) {
		xdgDir := t.TempDir()
		soroauthDir := filepath.Join(xdgDir, "soroauth")
		if err := os.MkdirAll(soroauthDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		xdgCfg := filepath.Join(soroauthDir, "config.json")
		if err := os.WriteFile(xdgCfg, []byte(`{
  "network": "testnet",
  "secret_env": "MY_SIGNING_SEED",
  "format": "json"
}`), 0o600); err != nil {
			t.Fatalf("write xdg config: %v", err)
		}

		v := loadVector(t, "v2_single_testnet")
		signer := vectorKeypair(t, "soroauth-vector-signer-1")
		env := map[string]string{
			"XDG_CONFIG_HOME": xdgDir,
			"MY_SIGNING_SEED": signer.Seed(),
		}

		// Sign without passing --network, --secret-env, or --json on the command line.
		stdout, _, err := runCLIEnv(t, env,
			"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567")
		if err != nil {
			t.Fatalf("sign with XDG config failed: %v", err)
		}
		var out signOutput
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("sign output is not JSON: %v\nstdout: %s", err, stdout)
		}
		signedVector := loadFullVector(t, "v2_single_testnet")
		if out.SignedEntry != signedVector {
			t.Errorf("signed entry mismatch\n want %s\n  got %s", signedVector, out.SignedEntry)
		}

		// Verify without passing --network or --json on the command line.
		vOut, _, err := runCLIEnv(t, env, "verify", "--entry", out.SignedEntry)
		if err != nil {
			t.Fatalf("verify with XDG config failed: %v", err)
		}
		var vReport verifyEntryOutput
		if err := json.Unmarshal([]byte(vOut), &vReport); err != nil {
			t.Fatalf("verify output is not JSON: %v\nstdout: %s", err, vOut)
		}
		if !vReport.Verified {
			t.Errorf("expected verified=true, got %+v", vReport)
		}
	})
}

// TestConfigRefusesSecretShapedValuesAndNeverEchoesThem proves the security
// acceptance criterion of #371: no secret value may be stored in the config
// file; only the name of an environment variable is permitted, and any
// secret-shaped value is refused without ever echoing the secret.
func TestConfigRefusesSecretShapedValuesAndNeverEchoesThem(t *testing.T) {
	realSigner := vectorKeypair(t, "soroauth-vector-signer-1")
	realSeed := realSigner.Seed()
	realAddr := realSigner.Address()
	hexSeed := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fakeSeed := "SNOTAREALSEEDATALL"
	pemKey := "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC"

	cases := []struct {
		name   string
		json   string
		secret string
	}{
		{
			name:   "real S... seed in secret_env",
			json:   `{"secret_env": "` + realSeed + `"}`,
			secret: realSeed,
		},
		{
			name:   "synthetic base32 S... seed in secret_env",
			json:   `{"secret_env": "` + fakeSeed + `"}`,
			secret: fakeSeed,
		},
		{
			name:   "64-char hex seed in secret_env",
			json:   `{"secret_env": "` + hexSeed + `"}`,
			secret: hexSeed,
		},
		{
			name:   "PEM block in secret_env",
			json:   `{"secret_env": "` + pemKey + `"}`,
			secret: pemKey,
		},
		{
			name:   "G... strkey in secret_env",
			json:   `{"secret_env": "` + realAddr + `"}`,
			secret: realAddr,
		},
		{
			name:   "real S... seed smuggled in network field",
			json:   `{"network": "` + realSeed + `"}`,
			secret: realSeed,
		},
		{
			name:   "real S... seed in forbidden 'seed' key",
			json:   `{"seed": "` + realSeed + `"}`,
			secret: realSeed,
		},
		{
			name:   "real S... seed in forbidden 'secret' key",
			json:   `{"secret": "` + realSeed + `"}`,
			secret: realSeed,
		},
		{
			name:   "real S... seed in forbidden 'private_key' key",
			json:   `{"private_key": "` + realSeed + `"}`,
			secret: realSeed,
		},
		{
			name:   "non-identifier in secret_env",
			json:   `{"secret_env": "not-an-env-var!"}`,
			secret: "not-an-env-var!",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeTempConfig(t, tc.json)
			stdout, stderr, err := runCLI(t, "doctor", "--config", cfgPath)
			if err == nil {
				t.Fatalf("expected refusal for %s, but command succeeded", tc.name)
			}
			if got := ExitCode(err); got != ExitUsageError {
				t.Errorf("exit code = %d, want %d (ExitUsageError)", got, ExitUsageError)
			}
			for stream, text := range map[string]string{
				"stdout": stdout,
				"stderr": stderr,
				"error":  err.Error(),
			} {
				if strings.Contains(text, tc.secret) {
					t.Errorf("%s leaked secret value %q: %s", stream, tc.secret, text)
				}
			}
		})
	}
}

// TestConfigMissingFileIsNotAnError proves that a missing config file is not an
// error, whether discovered via HOME/XDG_CONFIG_HOME or passed via --config.
func TestConfigMissingFileIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	missingPath := filepath.Join(t.TempDir(), "does-not-exist.json")
	stdout, _, err := runCLIEnv(t, map[string]string{
		"HOME": t.TempDir(),
	}, "doctor", "--config", missingPath, "--rpc-url", srv.URL, "--json")
	if err != nil {
		t.Fatalf("missing config file caused an error: %v", err)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Config.Loaded {
		t.Errorf("expected Config.Loaded = false for missing file, got true")
	}
}

// TestConfigUnparseableFileIsAnError proves that an unparseable config file,
// an unknown field, or an invalid format value is a usage error.
func TestConfigUnparseableFileIsAnError(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantMsg string
	}{
		{
			name:    "invalid JSON syntax",
			content: `{"network": "testnet"`,
			wantMsg: "parsing config file",
		},
		{
			name:    "unknown field",
			content: `{"network": "testnet", "unknown_option": true}`,
			wantMsg: "unknown field",
		},
		{
			name:    "trailing content after JSON object",
			content: `{"network": "testnet"} {"extra": 1}`,
			wantMsg: "trailing content",
		},
		{
			name:    "invalid format value",
			content: `{"format": "yaml"}`,
			wantMsg: "invalid format",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeTempConfig(t, tc.content)
			_, _, err := runCLI(t, "doctor", "--config", cfgPath)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if got := ExitCode(err); got != ExitUsageError {
				t.Errorf("exit code = %d, want %d", got, ExitUsageError)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}
