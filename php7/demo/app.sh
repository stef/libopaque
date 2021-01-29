#!/bin/sh

IFS=$(printf '\n\t')
set -o errexit -o nounset
if [ -n "${BASH_VERSION:-}" ]; then
	# shellcheck disable=SC2039
	set -o pipefail
fi
set -o xtrace

script_dir="$(
	cd "$(dirname "$0")"
	pwd -P
)"
cd "$script_dir"

LD_LIBRARY_PATH="$(pwd)/../../src" php -S 0.0.0.0:8080 router.php
