#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
exec python3 -m code.web_app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
