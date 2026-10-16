// Command docsite builds the repository's Markdown documentation into a
// navigable, searchable static HTML site with a version selector and links to
// the Go API reference on pkg.go.dev.
//
// The repository's Markdown files remain the single source of truth:
//
//   - Navigation sections, document order and one-line descriptions are parsed
//     directly from docs/README.md, so adding a document never requires
//     updating a separate generator configuration.
//   - Every Markdown file under docs/ must be listed in docs/README.md; an
//     unlisted file fails the build so the map and the site cannot drift.
//   - Every internal link and heading anchor across all rendered pages is
//     verified against the generated HTML before the build succeeds.
//
// Usage:
//
//	go run ./scripts/docsite --out _site --version v0.2.0
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const defaultPkgURL = "https://pkg.go.dev/github.com/soroauth/soroauth-go"

// Config holds the inputs for a documentation site build.
type Config struct {
	// Root is the repository root directory containing README.md and docs/.
	Root string
	// Out is the destination directory where the static site is written.
	Out string
	// Version is the release tag or revision documented by this build.
	Version string
	// Versions is the list of version strings offered by the version selector.
	Versions []string
	// PkgURL is the base URL for the Go API reference on pkg.go.dev.
	PkgURL string
}

// NavItem is one row parsed from docs/README.md.
type NavItem struct {
	// Label is the link text from docs/README.md.
	Label string
	// RelMD is the slash-separated path relative to the repository root.
	RelMD string
	// RelHTML is the slash-separated output HTML path relative to the site root.
	RelHTML string
	// Description is the "Answers" column from docs/README.md.
	Description string
	// Section is the heading under which this item appears in docs/README.md.
	Section string
}

// NavSection is a named group of navigation items from docs/README.md.
type NavSection struct {
	// Title is the section heading text.
	Title string
	// Items are the documents listed in that section's table.
	Items []NavItem
}

// SearchEntry is one document's record in search-index.json.
type SearchEntry struct {
	Title    string   `json:"title"`
	Path     string   `json:"path"`
	Section  string   `json:"section"`
	Summary  string   `json:"summary"`
	Headings []string `json:"headings"`
	Text     string   `json:"text"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("docsite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "repository root directory")
	out := fs.String("out", "_site", "output directory for the generated site")
	version := fs.String("version", "", "version documented by the site (defaults to git tag or dev)")
	versionsCSV := fs.String("versions", "", "comma-separated list of versions for the version selector")
	pkgURL := fs.String("pkg-url", defaultPkgURL, "Go API reference URL")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "docsite: unexpected positional arguments: %v\n", fs.Args())
		return 2
	}

	ver := strings.TrimSpace(*version)
	if ver == "" {
		ver = detectVersion(*root)
	}
	versions := parseVersions(*versionsCSV, ver, *root)

	cfg := Config{
		Root:     *root,
		Out:      *out,
		Version:  ver,
		Versions: versions,
		PkgURL:   strings.TrimRight(strings.TrimSpace(*pkgURL), "/"),
	}
	if err := BuildSite(cfg); err != nil {
		fmt.Fprintf(stderr, "docsite: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "docsite: built site in %s (version %s)\n", cfg.Out, cfg.Version)
	return 0
}

func detectVersion(root string) string {
	if v := strings.TrimSpace(os.Getenv("SOROAUTH_VERSION")); v != "" {
		return v
	}
	cmd := exec.Command("git", "-C", root, "describe", "--tags", "--always")
	out, err := cmd.Output()
	if err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return s
		}
	}
	return "dev"
}

func parseVersions(csv, current, root string) []string {
	seen := map[string]bool{}
	var list []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		list = append(list, v)
	}
	add(current)
	if strings.TrimSpace(csv) != "" {
		for _, part := range strings.Split(csv, ",") {
			add(part)
		}
	} else {
		cmd := exec.Command("git", "-C", root, "tag", "-l", "v*", "--sort=-v:refname")
		if out, err := cmd.Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				add(line)
			}
		}
	}
	add("main")
	return list
}

// BuildSite renders the documentation site from cfg.Root into cfg.Out and
// verifies that every document in docs/ is reachable and every internal link
// and fragment resolves.
func BuildSite(cfg Config) error {
	if strings.TrimSpace(cfg.Root) == "" {
		return fmt.Errorf("root directory is required")
	}
	if strings.TrimSpace(cfg.Out) == "" {
		return fmt.Errorf("output directory is required")
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if len(cfg.Versions) == 0 {
		cfg.Versions = []string{cfg.Version, "main"}
	}
	if cfg.PkgURL == "" {
		cfg.PkgURL = defaultPkgURL
	}

	sections, navByPath, err := parseDocsIndex(cfg.Root)
	if err != nil {
		return err
	}

	mdFiles, err := collectMarkdownFiles(cfg.Root, cfg.Out, navByPath)
	if err != nil {
		return err
	}
	mdSet := make(map[string]bool, len(mdFiles))
	for _, f := range mdFiles {
		mdSet[f] = true
	}

	if err := os.RemoveAll(cfg.Out); err != nil {
		return fmt.Errorf("cleaning output directory %s: %w", cfg.Out, err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.Out, "assets"), 0o755); err != nil {
		return err
	}

	assetsToCopy := map[string]bool{}
	dirsToIndex := map[string]bool{}
	var searchIndex []SearchEntry

	for _, relMD := range mdFiles {
		srcPath := filepath.Join(cfg.Root, filepath.FromSlash(relMD))
		raw, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", relMD, err)
		}
		res := renderMarkdown(string(raw), relMD, cfg.Root, mdSet)
		for _, a := range res.referencedAssets {
			assetsToCopy[a] = true
		}
		for _, d := range res.referencedDirs {
			dirsToIndex[d] = true
		}

		relHTML := mdToHTMLPath(relMD)
		title := res.title
		if title == "" {
			title = relMD
		}
		sectionName := "Repository"
		summary := ""
		if item, ok := navByPath[relMD]; ok {
			sectionName = item.Section
			summary = item.Description
		} else if relMD == "docs/README.md" {
			sectionName = "Start here"
			summary = "Map of every document in the repository and the question it answers."
		}

		pageHTML := wrapPageHTML(pageTemplateData{
			Title:       title,
			RelMD:       relMD,
			RelHTML:     relHTML,
			Summary:     summary,
			ContentHTML: res.html,
			Sections:    sections,
			Version:     cfg.Version,
			Versions:    cfg.Versions,
			PkgURL:      cfg.PkgURL,
		})

		dstPath := filepath.Join(cfg.Out, filepath.FromSlash(relHTML))
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dstPath, []byte(pageHTML), 0o644); err != nil {
			return err
		}

		// For README.md files, also emit an index.html in the same directory so
		// directory links and the site root resolve cleanly.
		if path.Base(relMD) == "README.md" {
			indexRel := path.Join(path.Dir(relHTML), "index.html")
			if path.Dir(relHTML) == "." {
				indexRel = "index.html"
			}
			indexDst := filepath.Join(cfg.Out, filepath.FromSlash(indexRel))
			if err := os.WriteFile(indexDst, []byte(pageHTML), 0o644); err != nil {
				return err
			}
		}

		searchIndex = append(searchIndex, SearchEntry{
			Title:    title,
			Path:     relHTML,
			Section:  sectionName,
			Summary:  summary,
			Headings: res.headings,
			Text:     res.plainText,
		})
	}

	// Copy static assets in docs/diagrams and docs/dashboards plus any other
	// repository files referenced by Markdown links.
	if err := collectStaticAssets(cfg.Root, assetsToCopy); err != nil {
		return err
	}
	for assetRel := range assetsToCopy {
		if err := copyRepoFile(cfg.Root, cfg.Out, assetRel); err != nil {
			return err
		}
	}

	// Generate lightweight directory index pages for linked source directories
	// that do not have their own README.md.
	for dirRel := range dirsToIndex {
		if err := writeDirListingPage(cfg, sections, dirRel); err != nil {
			return err
		}
	}

	if err := writeSiteSupportFiles(cfg, searchIndex); err != nil {
		return err
	}

	return verifySite(cfg.Out, sections, mdFiles)
}

var tableLinkPattern = regexp.MustCompile(`^\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*(.+?)\s*\|?\s*$`)

// parseDocsIndex reads docs/README.md and extracts the navigation sections and
// document entries, then verifies that every Markdown file under docs/ is
// listed in docs/README.md.
func parseDocsIndex(root string) ([]NavSection, map[string]NavItem, error) {
	indexPath := filepath.Join(root, "docs", "README.md")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading docs/README.md: %w", err)
	}

	var sections []NavSection
	byPath := map[string]NavItem{}
	currentSection := "Documentation"

	for lineNo, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if after, ok := strings.CutPrefix(line, "## "); ok {
			currentSection = strings.TrimSpace(after)
			sections = append(sections, NavSection{Title: currentSection})
			continue
		}
		m := tableLinkPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		label := strings.TrimSpace(m[1])
		target := strings.TrimSpace(m[2])
		desc := strings.TrimSpace(m[3])
		if strings.Contains(target, "#") {
			target = strings.SplitN(target, "#", 2)[0]
		}
		relMD := path.Clean(path.Join("docs", target))
		if strings.HasPrefix(relMD, "../") {
			return nil, nil, fmt.Errorf("docs/README.md:%d: link %q escapes repository root", lineNo+1, target)
		}
		fullPath := filepath.Join(root, filepath.FromSlash(relMD))
		info, err := os.Stat(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("docs/README.md:%d: linked file %q (%s) does not exist: %w", lineNo+1, target, relMD, err)
		}
		if info.IsDir() {
			relMD = path.Join(relMD, "README.md")
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relMD))); err != nil {
				return nil, nil, fmt.Errorf("docs/README.md:%d: linked directory %q has no README.md", lineNo+1, target)
			}
		}

		item := NavItem{
			Label:       label,
			RelMD:       relMD,
			RelHTML:     mdToHTMLPath(relMD),
			Description: stripInlineMarkdown(desc),
			Section:     currentSection,
		}
		if len(sections) == 0 {
			sections = append(sections, NavSection{Title: currentSection})
		}
		sections[len(sections)-1].Items = append(sections[len(sections)-1].Items, item)
		byPath[relMD] = item
	}

	if len(byPath) == 0 {
		return nil, nil, fmt.Errorf("docs/README.md contains no document table links")
	}

	// Ensure every Markdown file in docs/ is indexed in docs/README.md.
	docsDir := filepath.Join(root, "docs")
	var unindexed []string
	err = filepath.WalkDir(docsDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "docs/README.md" {
			return nil
		}
		if _, ok := byPath[relSlash]; !ok {
			unindexed = append(unindexed, relSlash)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("scanning docs/: %w", err)
	}
	if len(unindexed) > 0 {
		sort.Strings(unindexed)
		return nil, nil, fmt.Errorf("documents in docs/ missing from docs/README.md: %s", strings.Join(unindexed, ", "))
	}

	// Add docs/README.md itself as the first entry in "Start here" so the
	// documentation map is always one click away in the sidebar.
	mapItem := NavItem{
		Label:       "Documentation map",
		RelMD:       "docs/README.md",
		RelHTML:     "docs/README.html",
		Description: "Every document in the repository and the question it answers.",
		Section:     sections[0].Title,
	}
	sections[0].Items = append([]NavItem{mapItem}, sections[0].Items...)
	byPath["docs/README.md"] = mapItem

	return sections, byPath, nil
}

func collectMarkdownFiles(root, out string, navByPath map[string]NavItem) ([]string, error) {
	absOut, err := filepath.Abs(out)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var files []string

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		absP, err := filepath.Abs(p)
		if err == nil && absP == absOut {
			return filepath.SkipDir
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || strings.HasPrefix(name, ".venv") || name == "_site" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if !seen[relSlash] {
			seen[relSlash] = true
			files = append(files, relSlash)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for relMD := range navByPath {
		if !seen[relMD] {
			seen[relMD] = true
			files = append(files, relMD)
		}
	}
	sort.Strings(files)
	return files, nil
}

func mdToHTMLPath(relMD string) string {
	ext := path.Ext(relMD)
	if strings.EqualFold(ext, ".md") {
		return relMD[:len(relMD)-len(ext)] + ".html"
	}
	return relMD + ".html"
}

type renderedDoc struct {
	title            string
	html             string
	headings         []string
	plainText        string
	referencedAssets []string
	referencedDirs   []string
}

// renderMarkdown converts a Markdown document at relMD into HTML, rewriting
// internal links and assigning GitHub-compatible heading anchor IDs.
func renderMarkdown(src, relMD, root string, mdSet map[string]bool) renderedDoc {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out bytes.Buffer
	var plainWords []string
	var headings []string
	var title string
	slugCounts := map[string]int{}
	assetsSet := map[string]bool{}
	dirsSet := map[string]bool{}

	ctx := inlineContext{
		relMD:  relMD,
		root:   root,
		mdSet:  mdSet,
		assets: assetsSet,
		dirs:   dirsSet,
	}

	inCode := false
	codeFence := ""
	codeLang := ""
	var codeLines []string

	var paraLines []string
	flushParagraph := func() {
		if len(paraLines) == 0 {
			return
		}
		joined := strings.Join(paraLines, "\n")
		out.WriteString("<p>")
		out.WriteString(renderInline(joined, &ctx))
		out.WriteString("</p>\n")
		plainWords = append(plainWords, stripInlineMarkdown(joined))
		paraLines = nil
	}

	inList := "" // "ul" or "ol"
	closeList := func() {
		if inList != "" {
			out.WriteString("</" + inList + ">\n")
			inList = ""
		}
	}

	inBlockquote := false
	var quoteLines []string
	flushBlockquote := func() {
		if !inBlockquote {
			return
		}
		joined := strings.Join(quoteLines, "\n")
		out.WriteString("<blockquote><p>")
		out.WriteString(renderInline(joined, &ctx))
		out.WriteString("</p></blockquote>\n")
		plainWords = append(plainWords, stripInlineMarkdown(joined))
		quoteLines = nil
		inBlockquote = false
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if inCode {
			if isClosingFence(trimmed, codeFence) {
				out.WriteString("<pre><code")
				if codeLang != "" {
					out.WriteString(` class="language-` + html.EscapeString(codeLang) + `"`)
				}
				out.WriteString(">")
				out.WriteString(html.EscapeString(strings.Join(codeLines, "\n")))
				out.WriteString("</code></pre>\n")
				inCode = false
				codeFence = ""
				codeLang = ""
				codeLines = nil
			} else {
				codeLines = append(codeLines, line)
			}
			continue
		}

		// Fenced code block start
		if fence, lang, ok := parseOpeningFence(trimmed); ok {
			flushParagraph()
			closeList()
			flushBlockquote()
			inCode = true
			codeFence = fence
			codeLang = lang
			codeLines = nil
			continue
		}

		// HTML comment line
		if strings.HasPrefix(trimmed, "<!--") && strings.HasSuffix(trimmed, "-->") {
			flushParagraph()
			closeList()
			flushBlockquote()
			continue
		}

		// Blank line
		if trimmed == "" {
			flushParagraph()
			closeList()
			flushBlockquote()
			continue
		}

		// Heading (# through ######)
		if level, headingText, ok := parseHeading(line); ok {
			flushParagraph()
			closeList()
			flushBlockquote()
			baseSlug := githubSlug(headingText)
			count := slugCounts[baseSlug]
			slugCounts[baseSlug] = count + 1
			slug := baseSlug
			if count > 0 {
				slug = fmt.Sprintf("%s-%d", baseSlug, count)
			}
			cleanHeading := stripInlineMarkdown(headingText)
			if title == "" && level == 1 {
				title = cleanHeading
			}
			headings = append(headings, cleanHeading)
			plainWords = append(plainWords, cleanHeading)
			fmt.Fprintf(&out, "<h%d id=%q>%s</h%d>\n", level, slug, renderInline(headingText, &ctx), level)
			continue
		}

		// Horizontal rule
		if trimmed == "---" || trimmed == "***" || trimmed == "___" {
			flushParagraph()
			closeList()
			flushBlockquote()
			out.WriteString("<hr>\n")
			continue
		}

		// Pipe table
		if strings.HasPrefix(trimmed, "|") && i+1 < len(lines) && isTableSeparator(strings.TrimSpace(lines[i+1])) {
			flushParagraph()
			closeList()
			flushBlockquote()
			headers := splitTableRow(trimmed)
			i++ // consume separator line
			out.WriteString("<div class=\"table-wrap\"><table>\n<thead><tr>")
			for _, h := range headers {
				out.WriteString("<th>" + renderInline(h, &ctx) + "</th>")
				plainWords = append(plainWords, stripInlineMarkdown(h))
			}
			out.WriteString("</tr></thead>\n<tbody>\n")
			for i+1 < len(lines) {
				nextTrim := strings.TrimSpace(lines[i+1])
				if !strings.HasPrefix(nextTrim, "|") {
					break
				}
				i++
				cells := splitTableRow(nextTrim)
				out.WriteString("<tr>")
				for cIdx := 0; cIdx < len(headers); cIdx++ {
					cell := ""
					if cIdx < len(cells) {
						cell = cells[cIdx]
					}
					out.WriteString("<td>" + renderInline(cell, &ctx) + "</td>")
					plainWords = append(plainWords, stripInlineMarkdown(cell))
				}
				out.WriteString("</tr>\n")
			}
			out.WriteString("</tbody></table></div>\n")
			continue
		}

		// Blockquote
		if strings.HasPrefix(trimmed, ">") {
			flushParagraph()
			closeList()
			inBlockquote = true
			qText := strings.TrimSpace(strings.TrimPrefix(trimmed, ">"))
			if qText != "" {
				quoteLines = append(quoteLines, qText)
			}
			continue
		}
		if inBlockquote {
			flushBlockquote()
		}

		// Unordered list item
		if itemText, ok := parseUnorderedListItem(line); ok {
			flushParagraph()
			if inList != "ul" {
				closeList()
				out.WriteString("<ul>\n")
				inList = "ul"
			}
			// Consume indented continuation lines belonging to this list item.
			itemLines := []string{itemText}
			for i+1 < len(lines) && isListContinuation(lines[i+1]) {
				i++
				itemLines = append(itemLines, strings.TrimSpace(lines[i]))
			}
			joined := strings.Join(itemLines, " ")
			out.WriteString("<li>" + renderInline(joined, &ctx) + "</li>\n")
			plainWords = append(plainWords, stripInlineMarkdown(joined))
			continue
		}

		// Ordered list item
		if itemText, ok := parseOrderedListItem(line); ok {
			flushParagraph()
			if inList != "ol" {
				closeList()
				out.WriteString("<ol>\n")
				inList = "ol"
			}
			itemLines := []string{itemText}
			for i+1 < len(lines) && isListContinuation(lines[i+1]) {
				i++
				itemLines = append(itemLines, strings.TrimSpace(lines[i]))
			}
			joined := strings.Join(itemLines, " ")
			out.WriteString("<li>" + renderInline(joined, &ctx) + "</li>\n")
			plainWords = append(plainWords, stripInlineMarkdown(joined))
			continue
		}

		closeList()
		paraLines = append(paraLines, trimmed)
	}

	if inCode {
		out.WriteString("<pre><code>")
		out.WriteString(html.EscapeString(strings.Join(codeLines, "\n")))
		out.WriteString("</code></pre>\n")
	}
	flushParagraph()
	closeList()
	flushBlockquote()

	var assets []string
	for a := range assetsSet {
		assets = append(assets, a)
	}
	sort.Strings(assets)

	var dirs []string
	for d := range dirsSet {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	return renderedDoc{
		title:            title,
		html:             out.String(),
		headings:         headings,
		plainText:        strings.Join(plainWords, " "),
		referencedAssets: assets,
		referencedDirs:   dirs,
	}
}

func parseOpeningFence(trimmed string) (fence, lang string, ok bool) {
	for _, ch := range []byte{'`', '~'} {
		if len(trimmed) >= 3 && trimmed[0] == ch && trimmed[1] == ch && trimmed[2] == ch {
			j := 0
			for j < len(trimmed) && trimmed[j] == ch {
				j++
			}
			return trimmed[:j], strings.TrimSpace(trimmed[j:]), true
		}
	}
	return "", "", false
}

func isClosingFence(trimmed, openFence string) bool {
	if len(trimmed) < len(openFence) {
		return false
	}
	ch := openFence[0]
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] != ch {
			return false
		}
	}
	return true
}

func parseHeading(line string) (int, string, bool) {
	trimmed := strings.TrimLeft(line, " ")
	if len(line)-len(trimmed) > 3 || !strings.HasPrefix(trimmed, "#") {
		return 0, "", false
	}
	level := 0
	for level < len(trimmed) && trimmed[level] == '#' {
		level++
	}
	if level > 6 || level >= len(trimmed) || trimmed[level] != ' ' {
		return 0, "", false
	}
	text := strings.TrimSpace(strings.TrimRight(trimmed[level+1:], "# "))
	return level, text, true
}

// githubSlug computes the GitHub heading anchor ID for a Markdown heading.
func githubSlug(heading string) string {
	// Replace [text](url) with text before slugifying.
	s := inlineLinkPattern.ReplaceAllString(heading, "$1")
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

func isTableSeparator(line string) bool {
	if !strings.HasPrefix(line, "|") {
		return false
	}
	cells := splitTableRow(line)
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		c = strings.Trim(strings.TrimSpace(c), ":")
		if len(c) < 3 || strings.Trim(c, "-") != "" {
			return false
		}
	}
	return true
}

func splitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

func parseUnorderedListItem(line string) (string, bool) {
	trimmed := strings.TrimLeft(line, " ")
	for _, prefix := range []string{"- ", "* "} {
		if after, ok := strings.CutPrefix(trimmed, prefix); ok {
			return strings.TrimSpace(after), true
		}
	}
	return "", false
}

var orderedListPattern = regexp.MustCompile(`^\s*\d+\.\s+(.+)$`)

func parseOrderedListItem(line string) (string, bool) {
	m := orderedListPattern.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

func isListContinuation(line string) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}
	if !strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "\t") {
		return false
	}
	if _, ok := parseUnorderedListItem(line); ok {
		return false
	}
	if _, ok := parseOrderedListItem(line); ok {
		return false
	}
	return true
}

type inlineContext struct {
	relMD  string
	root   string
	mdSet  map[string]bool
	assets map[string]bool
	dirs   map[string]bool
}

var (
	inlineCodePattern  = regexp.MustCompile("`([^`]+)`")
	inlineImagePattern = regexp.MustCompile(`!\[([^\]]*)\]\(([^)]+)\)`)
	inlineLinkPattern  = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	inlineBoldPattern  = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	inlineEmphPattern  = regexp.MustCompile(`(?:^|(\s))_([^_]+)_(?:$|(\s|[.,;:!?)]))`)
)

func renderInline(text string, ctx *inlineContext) string {
	// Extract inline code spans first so brackets/underscores inside code are
	// never interpreted as links or emphasis.
	var codeSpans []string
	withPlaceholders := inlineCodePattern.ReplaceAllStringFunc(text, func(m string) string {
		sub := inlineCodePattern.FindStringSubmatch(m)
		idx := len(codeSpans)
		codeSpans = append(codeSpans, "<code>"+html.EscapeString(sub[1])+"</code>")
		return fmt.Sprintf("\x00CODE%d\x00", idx)
	})

	var htmlAtoms []string
	addAtom := func(rendered string) string {
		idx := len(htmlAtoms)
		htmlAtoms = append(htmlAtoms, rendered)
		return fmt.Sprintf("\x00ATOM%d\x00", idx)
	}

	// Images ![alt](src)
	withPlaceholders = inlineImagePattern.ReplaceAllStringFunc(withPlaceholders, func(m string) string {
		sub := inlineImagePattern.FindStringSubmatch(m)
		alt := html.EscapeString(sub[1])
		src := rewriteURL(sub[2], ctx, true)
		return addAtom(fmt.Sprintf(`<img src=%q alt=%q>`, src, alt))
	})

	// Links [label](href)
	withPlaceholders = inlineLinkPattern.ReplaceAllStringFunc(withPlaceholders, func(m string) string {
		sub := inlineLinkPattern.FindStringSubmatch(m)
		label := renderInlineLabel(sub[1], codeSpans)
		href := rewriteURL(sub[2], ctx, false)
		return addAtom(fmt.Sprintf(`<a href=%q>%s</a>`, href, label))
	})

	escaped := html.EscapeString(withPlaceholders)
	escaped = inlineBoldPattern.ReplaceAllString(escaped, "<strong>$1</strong>")
	escaped = inlineEmphPattern.ReplaceAllString(escaped, "$1<em>$2</em>$3")

	for idx, atom := range htmlAtoms {
		escaped = strings.ReplaceAll(escaped, fmt.Sprintf("\x00ATOM%d\x00", idx), atom)
	}
	for idx, code := range codeSpans {
		escaped = strings.ReplaceAll(escaped, fmt.Sprintf("\x00CODE%d\x00", idx), code)
	}
	return escaped
}

func renderInlineLabel(label string, codeSpans []string) string {
	escaped := html.EscapeString(label)
	escaped = inlineBoldPattern.ReplaceAllString(escaped, "<strong>$1</strong>")
	for idx, code := range codeSpans {
		escaped = strings.ReplaceAll(escaped, fmt.Sprintf("\x00CODE%d\x00", idx), code)
	}
	return escaped
}

func rewriteURL(rawURL string, ctx *inlineContext, isImage bool) string {
	u := strings.TrimSpace(rawURL)
	if u == "" ||
		strings.HasPrefix(u, "http://") ||
		strings.HasPrefix(u, "https://") ||
		strings.HasPrefix(u, "mailto:") ||
		strings.HasPrefix(u, "#") {
		return u
	}

	pathPart := u
	fragPart := ""
	if idx := strings.IndexByte(u, '#'); idx >= 0 {
		pathPart = u[:idx]
		fragPart = u[idx:]
	}

	baseDir := path.Dir(ctx.relMD)
	resolved := path.Clean(path.Join(baseDir, pathPart))
	if strings.HasPrefix(resolved, "../") {
		return u
	}

	if !isImage && strings.HasSuffix(strings.ToLower(resolved), ".md") {
		targetHTML := mdToHTMLPath(resolved)
		relLink, err := filepath.Rel(filepath.FromSlash(baseDir), filepath.FromSlash(targetHTML))
		if err == nil {
			return filepath.ToSlash(relLink) + fragPart
		}
		return targetHTML + fragPart
	}

	fullPath := filepath.Join(ctx.root, filepath.FromSlash(resolved))
	info, err := os.Stat(fullPath)
	if err == nil && info.IsDir() {
		readmeCand := path.Join(resolved, "README.md")
		if ctx.mdSet[readmeCand] {
			targetHTML := mdToHTMLPath(readmeCand)
			relLink, relErr := filepath.Rel(filepath.FromSlash(baseDir), filepath.FromSlash(targetHTML))
			if relErr == nil {
				return filepath.ToSlash(relLink) + fragPart
			}
		}
		ctx.dirs[resolved] = true
		targetHTML := path.Join(resolved, "index.html")
		relLink, relErr := filepath.Rel(filepath.FromSlash(baseDir), filepath.FromSlash(targetHTML))
		if relErr == nil {
			return filepath.ToSlash(relLink) + fragPart
		}
		return targetHTML + fragPart
	}

	if err == nil && !info.IsDir() {
		ctx.assets[resolved] = true
	}
	return pathPart + fragPart
}

func stripInlineMarkdown(s string) string {
	s = inlineImagePattern.ReplaceAllString(s, "$1")
	s = inlineLinkPattern.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "**", "")
	return strings.TrimSpace(s)
}

func collectStaticAssets(root string, assets map[string]bool) error {
	for _, sub := range []string{"docs/diagrams", "docs/dashboards"} {
		dir := filepath.Join(root, filepath.FromSlash(sub))
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			assets[filepath.ToSlash(rel)] = true
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func copyRepoFile(root, out, relSlash string) error {
	src := filepath.Join(root, filepath.FromSlash(relSlash))
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("copying asset %s: %w", relSlash, err)
	}
	dst := filepath.Join(out, filepath.FromSlash(relSlash))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func writeDirListingPage(cfg Config, sections []NavSection, dirRel string) error {
	dirPath := filepath.Join(cfg.Root, filepath.FromSlash(dirRel))
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<h1 id=%q>%s</h1>\n<p>Repository directory <code>%s</code>.</p>\n<ul>\n",
		githubSlug(dirRel), html.EscapeString(dirRel), html.EscapeString(dirRel))
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		childRel := path.Join(dirRel, name)
		if !e.IsDir() {
			_ = copyRepoFile(cfg.Root, cfg.Out, childRel)
			fmt.Fprintf(&b, "<li><a href=%q><code>%s</code></a></li>\n", html.EscapeString(name), html.EscapeString(name))
		} else {
			fmt.Fprintf(&b, "<li><code>%s/</code></li>\n", html.EscapeString(name))
		}
	}
	b.WriteString("</ul>\n")

	relHTML := path.Join(dirRel, "index.html")
	page := wrapPageHTML(pageTemplateData{
		Title:       dirRel,
		RelMD:       dirRel,
		RelHTML:     relHTML,
		Summary:     "Directory listing for " + dirRel,
		ContentHTML: b.String(),
		Sections:    sections,
		Version:     cfg.Version,
		Versions:    cfg.Versions,
		PkgURL:      cfg.PkgURL,
	})
	dst := filepath.Join(cfg.Out, filepath.FromSlash(relHTML))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, []byte(page), 0o644)
}

type pageTemplateData struct {
	Title       string
	RelMD       string
	RelHTML     string
	Summary     string
	ContentHTML string
	Sections    []NavSection
	Version     string
	Versions    []string
	PkgURL      string
}

func relativeToRoot(fromRelHTML, targetRelHTML string) string {
	baseDir := path.Dir(fromRelHTML)
	rel, err := filepath.Rel(filepath.FromSlash(baseDir), filepath.FromSlash(targetRelHTML))
	if err != nil {
		return targetRelHTML
	}
	return filepath.ToSlash(rel)
}

func wrapPageHTML(d pageTemplateData) string {
	cssHref := relativeToRoot(d.RelHTML, "assets/style.css")
	jsHref := relativeToRoot(d.RelHTML, "assets/search.js")
	searchIndexHref := relativeToRoot(d.RelHTML, "search-index.json")
	homeHref := relativeToRoot(d.RelHTML, "index.html")
	mapHref := relativeToRoot(d.RelHTML, "docs/README.html")

	versionedPkgURL := d.PkgURL
	if strings.HasPrefix(d.Version, "v") {
		versionedPkgURL = d.PkgURL + "@" + d.Version
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("  <meta charset=\"utf-8\">\n")
	b.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&b, "  <title>%s — soroauth-go (%s) documentation</title>\n", html.EscapeString(d.Title), html.EscapeString(d.Version))
	fmt.Fprintf(&b, "  <link rel=\"stylesheet\" href=%q>\n", cssHref)
	b.WriteString("</head>\n")
	fmt.Fprintf(&b, "<body data-search-index=%q data-current-path=%q data-version=%q>\n",
		searchIndexHref, d.RelHTML, d.Version)

	b.WriteString("  <header class=\"site-header\">\n")
	b.WriteString("    <div class=\"brand\">\n")
	fmt.Fprintf(&b, "      <a class=\"brand-title\" href=%q>soroauth-go</a>\n", homeHref)
	fmt.Fprintf(&b, "      <a class=\"brand-map\" href=%q>Documentation Map</a>\n", mapHref)
	fmt.Fprintf(&b, "      <span class=\"version-statement\">Documenting soroauth-go <strong>%s</strong></span>\n", html.EscapeString(d.Version))
	b.WriteString("    </div>\n")

	b.WriteString("    <div class=\"header-controls\">\n")
	b.WriteString("      <div class=\"search-box\">\n")
	b.WriteString("        <input id=\"doc-search\" type=\"search\" placeholder=\"Search documentation…\" aria-label=\"Search documentation\" autocomplete=\"off\">\n")
	b.WriteString("        <div id=\"doc-search-results\" class=\"search-results\" role=\"listbox\" hidden></div>\n")
	b.WriteString("      </div>\n")

	b.WriteString("      <label class=\"version-label\" for=\"version-selector\">Version\n")
	b.WriteString("        <select id=\"version-selector\" aria-label=\"Select documentation version\">\n")
	for _, v := range d.Versions {
		sel := ""
		if v == d.Version {
			sel = " selected"
		}
		fmt.Fprintf(&b, "          <option value=%q%s>%s</option>\n", v, sel, html.EscapeString(v))
	}
	b.WriteString("        </select>\n")
	b.WriteString("      </label>\n")

	fmt.Fprintf(&b, "      <a class=\"api-ref-link\" href=%q>Go API Reference (pkg.go.dev)</a>\n", versionedPkgURL)
	b.WriteString("    </div>\n")
	b.WriteString("  </header>\n")

	b.WriteString("  <div class=\"site-layout\">\n")
	b.WriteString("    <nav class=\"doc-sidebar\" aria-label=\"Documentation navigation\">\n")
	b.WriteString("      <div class=\"nav-section\">\n")
	b.WriteString("        <div class=\"nav-section-title\">Go API Reference</div>\n")
	b.WriteString("        <ul class=\"nav-list\">\n")
	fmt.Fprintf(&b, "          <li><a href=%q>soroauth (root package)</a></li>\n", versionedPkgURL)
	fmt.Fprintf(&b, "          <li><a href=%q>soroauth/remote</a></li>\n", d.PkgURL+"/remote")
	fmt.Fprintf(&b, "          <li><a href=%q>soroauth/rpcflow</a></li>\n", d.PkgURL+"/rpcflow")
	fmt.Fprintf(&b, "          <li><a href=%q>soroauth/server</a></li>\n", d.PkgURL+"/server")
	b.WriteString("        </ul>\n")
	b.WriteString("      </div>\n")

	for _, sec := range d.Sections {
		b.WriteString("      <div class=\"nav-section\">\n")
		fmt.Fprintf(&b, "        <div class=\"nav-section-title\">%s</div>\n", html.EscapeString(sec.Title))
		b.WriteString("        <ul class=\"nav-list\">\n")
		for _, item := range sec.Items {
			href := relativeToRoot(d.RelHTML, item.RelHTML)
			currentAttr := ""
			if item.RelHTML == d.RelHTML {
				currentAttr = ` aria-current="page" class="active"`
			}
			fmt.Fprintf(&b, "          <li><a href=%q title=%q%s>%s</a></li>\n",
				href, item.Description, currentAttr, html.EscapeString(item.Label))
		}
		b.WriteString("        </ul>\n")
		b.WriteString("      </div>\n")
	}
	b.WriteString("    </nav>\n")

	b.WriteString("    <main class=\"doc-main\">\n")
	b.WriteString("      <div class=\"doc-meta\">\n")
	fmt.Fprintf(&b, "        <span>Source: <code>%s</code></span>\n", html.EscapeString(d.RelMD))
	fmt.Fprintf(&b, "        <span>Version: <code>%s</code></span>\n", html.EscapeString(d.Version))
	if d.Summary != "" {
		fmt.Fprintf(&b, "        <p class=\"doc-summary\">%s</p>\n", html.EscapeString(d.Summary))
	}
	b.WriteString("      </div>\n")
	b.WriteString("      <article class=\"doc-content\">\n")
	b.WriteString(d.ContentHTML)
	b.WriteString("      </article>\n")
	b.WriteString("    </main>\n")
	b.WriteString("  </div>\n")
	fmt.Fprintf(&b, "  <script src=%q></script>\n", jsHref)
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

func writeSiteSupportFiles(cfg Config, searchIndex []SearchEntry) error {
	idxBytes, err := json.MarshalIndent(searchIndex, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.Out, "search-index.json"), idxBytes, 0o644); err != nil {
		return err
	}

	verBytes, err := json.MarshalIndent(struct {
		Current  string   `json:"current"`
		Versions []string `json:"versions"`
	}{
		Current:  cfg.Version,
		Versions: cfg.Versions,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.Out, "versions.json"), verBytes, 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(cfg.Out, ".nojekyll"), []byte(""), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.Out, "assets", "style.css"), []byte(siteCSS), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cfg.Out, "assets", "search.js"), []byte(siteJS), 0o644)
}

var (
	htmlHrefSrcPattern = regexp.MustCompile(`\b(?:href|src)="([^"]+)"`)
	htmlIDPattern      = regexp.MustCompile(`\bid="([^"]+)"`)
)

// verifySite checks that every document in docs/README.md and every Markdown
// file was emitted and that every internal link and #fragment anchor across the
// generated HTML resolves.
func verifySite(outDir string, sections []NavSection, mdFiles []string) error {
	for _, sec := range sections {
		for _, item := range sec.Items {
			p := filepath.Join(outDir, filepath.FromSlash(item.RelHTML))
			if _, err := os.Stat(p); err != nil {
				return fmt.Errorf("navigation item %q (%s) was not generated: %w", item.Label, item.RelHTML, err)
			}
		}
	}
	for _, relMD := range mdFiles {
		relHTML := mdToHTMLPath(relMD)
		p := filepath.Join(outDir, filepath.FromSlash(relHTML))
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("markdown file %s has no rendered HTML at %s: %w", relMD, relHTML, err)
		}
	}

	idsByFile := map[string]map[string]bool{}
	var htmlFiles []string
	err := filepath.WalkDir(outDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".html") {
			return nil
		}
		rel, err := filepath.Rel(outDir, p)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		htmlFiles = append(htmlFiles, relSlash)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		ids := map[string]bool{}
		for _, m := range htmlIDPattern.FindAllStringSubmatch(string(data), -1) {
			ids[m[1]] = true
		}
		idsByFile[relSlash] = ids
		return nil
	})
	if err != nil {
		return err
	}

	for _, relHTML := range htmlFiles {
		full := filepath.Join(outDir, filepath.FromSlash(relHTML))
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		baseDir := path.Dir(relHTML)
		for _, m := range htmlHrefSrcPattern.FindAllStringSubmatch(string(data), -1) {
			rawTarget := html.UnescapeString(strings.TrimSpace(m[1]))
			if rawTarget == "" ||
				strings.HasPrefix(rawTarget, "http://") ||
				strings.HasPrefix(rawTarget, "https://") ||
				strings.HasPrefix(rawTarget, "mailto:") {
				continue
			}
			pathPart := rawTarget
			fragPart := ""
			if idx := strings.IndexByte(rawTarget, '#'); idx >= 0 {
				pathPart = rawTarget[:idx]
				fragPart = rawTarget[idx+1:]
			}
			targetRel := relHTML
			if pathPart != "" {
				targetRel = path.Clean(path.Join(baseDir, pathPart))
			}
			if strings.HasPrefix(targetRel, "../") {
				return fmt.Errorf("%s: link %q escapes site root", relHTML, rawTarget)
			}
			targetDisk := filepath.Join(outDir, filepath.FromSlash(targetRel))
			info, err := os.Stat(targetDisk)
			if err != nil {
				return fmt.Errorf("%s: broken internal link %q (resolved to %s)", relHTML, rawTarget, targetRel)
			}
			if info.IsDir() {
				targetRel = path.Join(targetRel, "index.html")
				if _, err := os.Stat(filepath.Join(outDir, filepath.FromSlash(targetRel))); err != nil {
					return fmt.Errorf("%s: broken directory link %q (missing %s)", relHTML, rawTarget, targetRel)
				}
			}
			if fragPart != "" && strings.HasSuffix(strings.ToLower(targetRel), ".html") {
				if !idsByFile[targetRel][fragPart] {
					return fmt.Errorf("%s: broken anchor #%s in link %q (target %s)", relHTML, fragPart, rawTarget, targetRel)
				}
			}
		}
	}
	return nil
}

const siteCSS = `:root {
  --bg: #ffffff;
  --fg: #111827;
  --muted: #4b5563;
  --border: #e5e7eb;
  --accent: #0f62fe;
  --code-bg: #f3f4f6;
  --sidebar-bg: #f9fafb;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  color: var(--fg);
  background: var(--bg);
  line-height: 1.6;
}
.site-header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid var(--border);
  background: var(--sidebar-bg);
  position: sticky;
  top: 0;
  z-index: 20;
}
.brand { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
.brand-title { font-weight: 700; font-size: 1.15rem; color: var(--fg); text-decoration: none; }
.brand-map { color: var(--accent); text-decoration: none; font-size: 0.9rem; font-weight: 500; }
.version-statement { font-size: 0.85rem; color: var(--muted); }
.header-controls { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.search-box { position: relative; }
#doc-search {
  padding: 0.35rem 0.65rem;
  border: 1px solid var(--border);
  border-radius: 4px;
  min-width: 240px;
  font-size: 0.9rem;
}
.search-results {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  min-width: 340px;
  max-height: 400px;
  overflow-y: auto;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
  margin-top: 0.25rem;
  z-index: 30;
}
.search-result-item {
  display: block;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border);
  text-decoration: none;
  color: var(--fg);
}
.search-result-item:hover { background: var(--code-bg); }
.search-result-title { font-weight: 600; font-size: 0.9rem; }
.search-result-meta { font-size: 0.78rem; color: var(--muted); }
.version-label { font-size: 0.85rem; color: var(--muted); display: flex; align-items: center; gap: 0.35rem; }
.api-ref-link {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--accent);
  text-decoration: none;
  padding: 0.3rem 0.6rem;
  border: 1px solid var(--accent);
  border-radius: 4px;
}
.site-layout {
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  min-height: calc(100vh - 56px);
}
.doc-sidebar {
  border-right: 1px solid var(--border);
  background: var(--sidebar-bg);
  padding: 1rem;
  overflow-y: auto;
}
.nav-section { margin-bottom: 1.2rem; }
.nav-section-title {
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  margin-bottom: 0.35rem;
}
.nav-list { list-style: none; padding: 0; margin: 0; }
.nav-list li { margin: 0.15rem 0; }
.nav-list a {
  display: block;
  padding: 0.2rem 0.45rem;
  border-radius: 4px;
  color: var(--fg);
  text-decoration: none;
  font-size: 0.88rem;
}
.nav-list a:hover { background: var(--code-bg); }
.nav-list a.active { background: var(--accent); color: #ffffff; font-weight: 600; }
.doc-main { padding: 1.5rem 2.25rem; max-width: 960px; }
.doc-meta {
  font-size: 0.82rem;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.75rem;
  margin-bottom: 1.25rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
}
.doc-summary { width: 100%; margin: 0.25rem 0 0 0; }
.doc-content h1, .doc-content h2, .doc-content h3 { margin-top: 1.6rem; }
.doc-content pre {
  background: var(--code-bg);
  padding: 0.85rem 1rem;
  border-radius: 6px;
  overflow-x: auto;
}
.doc-content code {
  background: var(--code-bg);
  padding: 0.1rem 0.3rem;
  border-radius: 3px;
  font-size: 0.88em;
}
.doc-content pre code { padding: 0; background: none; }
.table-wrap { overflow-x: auto; }
.doc-content table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
.doc-content th, .doc-content td {
  border: 1px solid var(--border);
  padding: 0.45rem 0.65rem;
  text-align: left;
  font-size: 0.9rem;
}
.doc-content th { background: var(--sidebar-bg); }
.doc-content img { max-width: 100%; height: auto; }
@media (max-width: 820px) {
  .site-layout { grid-template-columns: 1fr; }
  .doc-sidebar { border-right: none; border-bottom: 1px solid var(--border); }
}
`

const siteJS = `(function () {
  var body = document.body;
  var indexUrl = body.getAttribute("data-search-index") || "search-index.json";
  var currentPath = body.getAttribute("data-current-path") || "index.html";
  var currentVersion = body.getAttribute("data-version") || "dev";
  var input = document.getElementById("doc-search");
  var resultsBox = document.getElementById("doc-search-results");
  var versionSelect = document.getElementById("version-selector");
  var indexPromise = null;

  function rootPrefix() {
    var depth = currentPath.split("/").length - 1;
    var prefix = "";
    for (var i = 0; i < depth; i++) {
      prefix += "../";
    }
    return prefix;
  }

  function loadIndex() {
    if (!indexPromise) {
      indexPromise = fetch(indexUrl).then(function (r) { return r.json(); });
    }
    return indexPromise;
  }

  if (input && resultsBox) {
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      if (!q) {
        resultsBox.hidden = true;
        resultsBox.innerHTML = "";
        return;
      }
      loadIndex().then(function (entries) {
        var matches = entries.filter(function (e) {
          var hay = (e.title + " " + e.summary + " " + (e.headings || []).join(" ") + " " + e.text).toLowerCase();
          return hay.indexOf(q) !== -1;
        }).slice(0, 12);
        resultsBox.innerHTML = "";
        if (matches.length === 0) {
          var empty = document.createElement("div");
          empty.className = "search-result-item";
          empty.textContent = "No matching documents.";
          resultsBox.appendChild(empty);
        } else {
          var prefix = rootPrefix();
          matches.forEach(function (m) {
            var a = document.createElement("a");
            a.className = "search-result-item";
            a.href = prefix + m.path;
            var t = document.createElement("div");
            t.className = "search-result-title";
            t.textContent = m.title;
            var meta = document.createElement("div");
            meta.className = "search-result-meta";
            meta.textContent = m.section + (m.summary ? " — " + m.summary : "");
            a.appendChild(t);
            a.appendChild(meta);
            resultsBox.appendChild(a);
          });
        }
        resultsBox.hidden = false;
      }).catch(function () {});
    });
  }

  if (versionSelect) {
    versionSelect.addEventListener("change", function () {
      var targetVer = versionSelect.value;
      if (!targetVer || targetVer === currentVersion) {
        return;
      }
      if (targetVer === "main") {
        window.location.href = "https://github.com/soroauth/soroauth-go/tree/main/docs";
      } else {
        window.location.href = "https://github.com/soroauth/soroauth-go/tree/" + encodeURIComponent(targetVer) + "/docs";
      }
    });
  }
})();
`
