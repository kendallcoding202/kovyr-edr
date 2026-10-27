#!/usr/bin/env bash
# Builds the Kovyr Protection Alarm MSI (Windows x64) on Linux.
#
#   installer/build-msi.sh [OUT_DIR]        (default: dist/installer)
#
# Needs Go and wixl from msitools (Debian/Ubuntu: apt-get install wixl).
# Writes OUT_DIR/kovyr-protection-alarm-x64.msi, its SHA256SUMS, and the
# kovyr-agent.exe (windows/amd64) it holds.
# The MSI is not code-signed yet.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/installer}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$root"

command -v wixl >/dev/null || { echo "wixl not found: apt-get install wixl (msitools)" >&2; exit 1; }

version=$(go run ./cmd/kovyr-agent version)
if ! [[ $version =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}$ ]]; then
	echo "unexpected agent version '$version'" >&2
	exit 1
fi

exe=$out/kovyr-agent.exe
msi=$out/kovyr-protection-alarm-x64.msi
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$exe" ./cmd/kovyr-agent
wixl --arch x64 -D Version="$version" -D AgentExe="$exe" -o "$msi" installer/kovyr-agent.wxs

# The rows the install depends on must be there: wixl skips some elements
# it does not understand with only a warning.
need() { # table, fixed string that must appear in it
	if ! msiinfo export "$msi" "$1" | grep -qF -- "$2"; then
		echo "the MSI's $1 table lacks '$2'" >&2
		exit 1
	fi
}
need CustomAction 'service install --server "[SERVER]" --dev-insecure=[DEV_INSECURE] --create-key --start'
need ServiceControl KovyrAgent
need Upgrade 76817CD3-D389-4C31-B3EF-78D8DF5D7572
need LaunchCondition KOVYR_SERVICE_PRESENT
need InstallExecuteSequence $'RemoveExistingProducts\t\t1401'
need InstallExecuteSequence $'KovyrInstallService\tNOT Installed\t6502'

(cd "$out" && sha256sum "$(basename "$msi")" > SHA256SUMS)
echo "Built $msi (Kovyr Protection Alarm $version, x64, unsigned)"
