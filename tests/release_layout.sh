#!/usr/bin/env bash
# Checks the user phase of both scripts in the release archive layout (bin/
# instead of a source tree) without cargo and without administrator access.
set -euo pipefail

usage="Usage: $0 TARGET_RELEASE_DIR"
(( $# == 1 )) || { printf '%s\n' "$usage" >&2; exit 2; }
release_dir="$(cd -- "$1" && pwd)"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

archive="$work/nwtop-test-linux"
mkdir -p "$archive/bin" "$archive/scripts" "$work/home" "$work/fake"
install -m 755 "$release_dir/nwtop" "$release_dir/nwtop-collector" "$archive/bin/"
install -m 755 "$repo_dir/scripts/install.sh" "$repo_dir/scripts/setup-capture.sh" "$archive/scripts/"
# Record the root-phase invocation instead of authenticating.
printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/pkexec-args"\n' "$work" > "$work/fake/pkexec"
chmod 755 "$work/fake/pkexec"
# A PATH without cargo proves the archive installs without a Rust toolchain.
path="$work/fake:/usr/sbin:/usr/bin:/sbin:/bin"
if PATH="$path" command -v cargo >/dev/null; then
    printf 'cargo must not be on the test PATH\n' >&2
    exit 1
fi

HOME="$work/home" PATH="$path" "$archive/scripts/install.sh" >/dev/null
cmp -- "$archive/bin/nwtop" "$work/home/.local/bin/nwtop"
if HOME="$work/home" PATH="$path" "$archive/scripts/install.sh" --extended-attribution 2>/dev/null; then
    printf 'Release install accepted --extended-attribution\n' >&2
    exit 1
fi

PATH="$path" "$archive/scripts/setup-capture.sh" --allow-shared-group >/dev/null
mapfile -t args < "$work/pkexec-args"
read -r digest _ < <(sha256sum -- "$archive/bin/nwtop-collector")
[[ "${args[2]}" == --install && "${args[3]}" == "$archive/bin/nwtop-collector" && "${args[6]}" == "$digest" ]] || {
    printf 'Unexpected root-phase arguments: %s\n' "${args[*]}" >&2
    exit 1
}
if PATH="$path" "$archive/scripts/setup-capture.sh" --allow-shared-group --extended-attribution 2>/dev/null; then
    printf 'Release setup accepted --extended-attribution\n' >&2
    exit 1
fi
printf 'PASS release layout: install without cargo, helper digest handed to the root phase, extended refused\n'
