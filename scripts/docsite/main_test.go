package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSiteAgainstRepository(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	outDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--root", repoRoot,
		"--out", outDir,
		"--version", "v0.2.0",
		"--versions", "v0.2.0,v0.1.0,main",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exited %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "built site in") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}

	// Verify every .md file in docs/ was rendered into the output site.
	entries, err := os.ReadDir(filepath.Join(repoRoot, "docs"))
	if err != nil {
		t.Fatalf("reading docs/: %v", err)
	}
	mdCount := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		mdCount++
		htmlName := strings.TrimSuffix(e.Name(), ".md") + ".html"
		renderedPath := filepath.Join(outDir, "docs", htmlName)
		data, err := os.ReadFile(renderedPath)
		if err != nil {
			t.Fatalf("expected rendered file %s: %v", renderedPath, err)
		}
		page := string(data)
		if !strings.Contains(page, "Documenting soroauth-go <strong>v0.2.0</strong>") {
			t.Errorf("%s missing version statement", htmlName)
		}
		if !strings.Contains(page, `id="version-selector"`) || !strings.Contains(page, `<option value="v0.1.0">v0.1.0</option>`) {
			t.Errorf("%s missing version selector options", htmlName)
		}
		if !strings.Contains(page, "https://pkg.go.dev/github.com/soroauth/soroauth-go@v0.2.0") {
			t.Errorf("%s missing versioned Go API reference link", htmlName)
		}
		if !strings.Contains(page, `id="doc-search"`) {
			t.Errorf("%s missing search input", htmlName)
		}
	}
	if mdCount < 18 {
		t.Fatalf("expected at least 18 documents in docs/, found %d", mdCount)
	}

	// Verify search-index.json is populated and valid JSON.
	idxBytes, err := os.ReadFile(filepath.Join(outDir, "search-index.json"))
	if err != nil {
		t.Fatalf("reading search-index.json: %v", err)
	}
	var searchEntries []SearchEntry
	if err := json.Unmarshal(idxBytes, &searchEntries); err != nil {
		t.Fatalf("unmarshalling search-index.json: %v", err)
	}
	if len(searchEntries) < mdCount {
		t.Fatalf("expected at least %d search index entries, got %d", mdCount, len(searchEntries))
	}
}

func TestUnindexedDocInDocsDirFails(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	docsReadme := "# Documentation\n\n## Start here\n\n| Document | Answers |\n| --- | --- |\n| [README](../README.md) | Root doc |\n| [faq](faq.md) | FAQ |\n"
	if err := os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte(docsReadme), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "faq.md"), []byte("# FAQ\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Add an unindexed document in docs/.
	if err := os.WriteFile(filepath.Join(root, "docs", "orphan.md"), []byte("# Orphan\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := BuildSite(Config{
		Root:    root,
		Out:     filepath.Join(t.TempDir(), "site"),
		Version: "v0.1.0",
	})
	if err == nil || !strings.Contains(err.Error(), "docs/orphan.md") {
		t.Fatalf("expected error naming docs/orphan.md, got %v", err)
	}
}

func TestBrokenInternalLinkAndAnchorDetection(t *testing.T) {
	t.Run("broken link", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Root\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		docsReadme := "# Docs\n\n## Guides\n\n| Document | Answers |\n| --- | --- |\n| [README](../README.md) | Root |\n| [guide](guide.md) | A guide |\n"
		if err := os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte(docsReadme), 0o644); err != nil {
			t.Fatal(err)
		}
		guide := "# Guide\n\nSee [missing](does-not-exist.md).\n"
		if err := os.WriteFile(filepath.Join(root, "docs", "guide.md"), []byte(guide), 0o644); err != nil {
			t.Fatal(err)
		}
		err := BuildSite(Config{Root: root, Out: filepath.Join(t.TempDir(), "out"), Version: "dev"})
		if err == nil || !strings.Contains(err.Error(), "does-not-exist.html") {
			t.Fatalf("expected broken internal link error for does-not-exist.html, got %v", err)
		}
	})

	t.Run("broken anchor", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Root\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		docsReadme := "# Docs\n\n## Guides\n\n| Document | Answers |\n| --- | --- |\n| [README](../README.md) | Root |\n| [guide](guide.md) | A guide |\n"
		if err := os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte(docsReadme), 0o644); err != nil {
			t.Fatal(err)
		}
		guide := "# Guide\n\nJump to [nonexistent](#no-such-section).\n"
		if err := os.WriteFile(filepath.Join(root, "docs", "guide.md"), []byte(guide), 0o644); err != nil {
			t.Fatal(err)
		}
		err := BuildSite(Config{Root: root, Out: filepath.Join(t.TempDir(), "out"), Version: "dev"})
		if err == nil || !strings.Contains(err.Error(), "broken anchor #no-such-section") {
			t.Fatalf("expected broken anchor error, got %v", err)
		}
	})
}

func TestRunFlagsAndMarkdownFeatures(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--unknown-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 on unknown flag, got %d", code)
	}
	stderr.Reset()
	if code := run([]string{"extra-arg"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 on positional arg, got %d", code)
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs", "diagrams"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pkgdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkgdir", "code.go"), []byte("package pkgdir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "diagrams", "flow.svg"), []byte("<svg></svg>"), 0o644); err != nil {
		t.Fatal(err)
	}
	docsReadme := "# Docs\n\n## Guides\n\n| Document | Answers |\n| --- | --- |\n| [README](../README.md) | Root |\n| [guide](guide.md) | Guide desc |\n"
	if err := os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte(docsReadme), 0o644); err != nil {
		t.Fatal(err)
	}
	guide := strings.Join([]string{
		"# Guide Title",
		"",
		"<!-- comment -->",
		"",
		"Paragraph with **bold**, _italic_, and `code [not-a-link](x)`.",
		"",
		"![diagram](diagrams/flow.svg)",
		"",
		"Link to [dir](../pkgdir) and [dup heading](#section-1).",
		"",
		"## Section",
		"",
		"- item one",
		"  continued line",
		"- item two",
		"",
		"1. first",
		"   continued ordered",
		"2. second",
		"",
		"> A blockquote",
		"> second line",
		"",
		"---",
		"",
		"## Section",
		"",
		"```sh",
		"echo <hello>",
		"```",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "docs", "guide.md"), []byte(guide), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SOROAUTH_VERSION", "v0.9.0")
	out := filepath.Join(t.TempDir(), "site")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--root", root, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("run failed (%d): %s", code, stderr.String())
	}
}
