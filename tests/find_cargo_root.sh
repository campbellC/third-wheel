#!/usr/bin/env bash

set -exuo pipefail

FILE="Cargo.toml"
CWD=`pwd`
while [[ "$CWD" != "/" ]]; do
    if [ -f "$FILE" ]; then
        echo "$CWD";
        break;
    else
        cd ..
        CWD=`pwd`
    fi
done
