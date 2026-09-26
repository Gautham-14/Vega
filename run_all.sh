#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec sh ./Aegis.command "$@"
