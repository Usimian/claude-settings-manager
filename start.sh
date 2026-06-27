#!/usr/bin/env bash
# Launch the Claude Settings Manager (local web app, no dependencies).
cd "$(dirname "$0")"
exec python3 server.py "$@"
