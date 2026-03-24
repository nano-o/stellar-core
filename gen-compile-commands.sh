#!/bin/bash
# Regenerate compile_commands.json by removing src/ object files and
# rebuilding under bear. ccache makes this fast if the cache is warm.
set -euo pipefail

cd "$(dirname "$0")"

export PATH="/usr/lib/ccache:$PATH"

find src/ -name '*.o' -delete
bear -- make -j4
