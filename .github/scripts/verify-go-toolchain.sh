#!/usr/bin/env bash
# Checks the Go toolchain that builds the MSI's agent, before anything is
# built with it.
#
# actions/setup-go downloads Go from actions/go-versions (a repackaged copy
# of the official release) and checks no checksum. The go command can
# fetch the same release as the module golang.org/toolchain from
# proxy.golang.org and verify it against the checksum database
# (sum.golang.org). This script does that and requires:
#   - `go` is exactly the version on go.mod's go line;
#   - every file of the verified release is byte-for-byte the same in
#     GOROOT;
#   - GOROOT holds nothing more, apart from the top-level api, doc, misc
#     and test folders and setup.sh, which the module leaves out and which
#     no build reads.
# It prints the version and GOROOT for the build log.
#
#   .github/scripts/verify-go-toolchain.sh        (from the repo root)
set -euo pipefail

want="go$(awk '$1 == "go" { print $2; exit }' go.mod)"
got=$(GOTOOLCHAIN=local go env GOVERSION)
goroot=$(GOTOOLCHAIN=local go env GOROOT)
platform="$(GOTOOLCHAIN=local go env GOHOSTOS)-$(GOTOOLCHAIN=local go env GOHOSTARCH)"
echo "Go: $got ($platform) at $goroot"
if [ "$got" != "$want" ]; then
	echo "::error::Go is $got but go.mod says $want" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
mod="golang.org/toolchain@v0.0.1-$got.$platform"
# A fresh module cache, the public proxy and the checksum database, with
# nothing in the environment allowed to skip the check.
(cd "$tmp" && env GOTOOLCHAIN=local GOFLAGS= GOMODCACHE="$tmp/mod" \
	GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
	GONOSUMDB= GONOSUMCHECK= GONOPROXY= GOPRIVATE= GOINSECURE= \
	go mod download "$mod")
verified="$tmp/mod/$mod"

# One "sha256  ./path" line per file, sorted. The module stores each of
# the release's go.mod files as _go.mod (a module zip can't nest go.mod
# files), so those are compared as go.mod.
list() { # dir, find arguments...
	local dir=$1
	shift
	(cd "$dir" && find . -type f "$@" -print0 | xargs -0 sha256sum)
}
list "$verified" | sed 's#/_go\.mod$#/go.mod#' | LC_ALL=C sort -k2 >"$tmp/verified.txt"
list "$goroot" ! -path './api/*' ! -path './doc/*' ! -path './misc/*' \
	! -path './test/*' ! -path ./setup.sh | LC_ALL=C sort -k2 >"$tmp/installed.txt"

if ! diff -u "$tmp/verified.txt" "$tmp/installed.txt" >"$tmp/diff.txt"; then
	echo "::error::GOROOT ($goroot) is not the verified $mod" >&2
	head -n 40 "$tmp/diff.txt" >&2
	exit 1
fi
echo "GOROOT matches $mod ($(wc -l <"$tmp/verified.txt") files, verified against sum.golang.org)"
