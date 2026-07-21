#!/bin/bash
# Regenerate compile_commands.json by removing src/ object files and
# rebuilding under bear. ccache makes this fast if the cache is warm.
# If the database is generated in a different filesystem view (for example
# inside the dev container), COMPILE_COMMANDS_TARGET_ROOT can rewrite absolute
# paths to match the editor's workspace path.
set -euo pipefail

cd "$(dirname "$0")"

SOURCE_ROOT="$(pwd -P)"
TARGET_ROOT="${COMPILE_COMMANDS_TARGET_ROOT:-$SOURCE_ROOT}"

USE_CCACHE="${USE_CCACHE:-1}"
if [ "${USE_CCACHE}" = "1" ]; then
    export PATH="/usr/lib/ccache:$PATH"
fi

MAKE_JOBS="${MAKE_JOBS:-4}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$MAKE_JOBS}"

find src/ -name '*.o' -delete
bear -- make -j"${MAKE_JOBS}"

if [ "${TARGET_ROOT}" != "${SOURCE_ROOT}" ]; then
    command -v jq >/dev/null 2>&1 || {
        echo "jq is required when COMPILE_COMMANDS_TARGET_ROOT is set" >&2
        exit 1
    }

    tmpfile="$(mktemp compile_commands.json.XXXXXX)"
    trap 'rm -f "${tmpfile}"' EXIT
    jq --arg from "${SOURCE_ROOT}" --arg to "${TARGET_ROOT}" '
        map(.directory |= sub("^" + $from; $to)
            | .file |= sub("^" + $from; $to)
            | .output |= sub("^" + $from; $to)
            | .arguments |= map(if type == "string"
                                then sub("^" + $from; $to)
                                else .
                                end))
    ' compile_commands.json > "${tmpfile}"
    mv "${tmpfile}" compile_commands.json
    trap - EXIT
fi
