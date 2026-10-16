#!/usr/bin/env bash
#
# Render the Homebrew formula for one release from its checksums file.
#
# The formula (packaging/homebrew/soroauth.rb.tmpl) is a template; this script
# fills in the version, the download base URL and the four per-platform
# SHA-256s. It is what keeps the tap from going stale: the release workflow runs
# it on every `v*` tag and pushes the result, so nobody has to remember to bump
# a formula by hand.
#
# The checksums file is the same one the release publishes (checksums.txt), so
# the hashes are computed once, in the release, and reused here rather than
# recomputed.
#
# Usage:
#   scripts/gen-formula.sh --version v0.2.0 \
#     --checksums checksums.txt \
#     --base-url https://github.com/soroauth/soroauth-go/releases/download/v0.2.0 \
#     --out soroauth.rb
#
# --base-url may be a file:// URL, which is how CI renders a formula against
# binaries it built locally and installs it without a published release.
#
# Exit status: 0 on success, 1 on a usage error or a missing checksum.
set -euo pipefail

here="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
template="$here/packaging/homebrew/soroauth.rb.tmpl"

version=''
checksums=''
base_url=''
out=''

usage() {
  sed -n '/^# Usage:/,/^# Exit status:/p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "gen-formula: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version needs a value"
      version="$2"
      shift 2
      ;;
    --checksums)
      [ $# -ge 2 ] || die "--checksums needs a value"
      checksums="$2"
      shift 2
      ;;
    --base-url)
      [ $# -ge 2 ] || die "--base-url needs a value"
      base_url="$2"
      shift 2
      ;;
    --out)
      [ $# -ge 2 ] || die "--out needs a value"
      out="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument '$1' (see --help)"
      ;;
  esac
done

[ -n "$version" ] || die "--version is required"
[ -n "$checksums" ] || die "--checksums is required"
[ -n "$base_url" ] || die "--base-url is required"
[ -n "$out" ] || die "--out is required"
[ -f "$checksums" ] || die "checksums file '$checksums' does not exist"
[ -f "$template" ] || die "template '$template' does not exist"

# sha_for prints the recorded SHA-256 for one release asset, or fails. A missing
# line is a hard error rather than an empty placeholder: a formula with an empty
# sha256 would download whatever the URL served, which is the opposite of what
# the checksum is for.
sha_for() {
  local asset="soroauth-$1.tar.gz" digest
  digest="$(awk -v want="$asset" '$2 == want { print $1 }' "$checksums")"
  [ -n "$digest" ] || die "no checksum for '${asset}' in ${checksums}"
  case "$digest" in
    # sha256sum and shasum both print 64 lowercase hex characters.
    *[!0-9a-f]* | '') die "'${asset}': '${digest}' is not a sha256 digest" ;;
  esac
  [ "${#digest}" -eq 64 ] || die "'${asset}': digest '${digest}' is not 64 hex characters"
  printf '%s\n' "$digest"
}

sha_darwin_amd64="$(sha_for darwin-amd64)"
sha_darwin_arm64="$(sha_for darwin-arm64)"
sha_linux_amd64="$(sha_for linux-amd64)"
sha_linux_arm64="$(sha_for linux-arm64)"

# sed replacement text treats \ and & specially; escape them in the values so a
# URL containing them cannot corrupt the output.
escape() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

cp "$template" "$out"
for pair in \
  "VERSION=$(escape "$version")" \
  "BASE_URL=$(escape "$base_url")" \
  "SHA_DARWIN_AMD64=$(escape "$sha_darwin_amd64")" \
  "SHA_DARWIN_ARM64=$(escape "$sha_darwin_arm64")" \
  "SHA_LINUX_AMD64=$(escape "$sha_linux_amd64")" \
  "SHA_LINUX_ARM64=$(escape "$sha_linux_arm64")"; do
  key="${pair%%=*}"
  value="${pair#*=}"
  sed -i.bak "s|@@${key}@@|${value}|g" "$out"
done
rm -f "$out.bak"

if grep -q '@@' "$out"; then
  die "the rendered formula still contains a placeholder: $(grep -o '@@[A-Z_]*@@' "$out" | sort -u | tr '\n' ' ')"
fi

echo "wrote $out (soroauth $version)"
