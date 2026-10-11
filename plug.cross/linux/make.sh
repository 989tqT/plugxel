#!/bin/bash
set -e

if [ "$#" -eq 0 ]; then
    python3 scripts/builder.py
else
    python3 scripts/builder.py "$1"
fi
