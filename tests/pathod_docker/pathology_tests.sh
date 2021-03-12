#!/usr/bin/env bash

trap 'kill $(jobs -p) || echo "no jobs running"' EXIT
set -uoex pipefail




/tmp/pathod &
echo "Sleeping to let pathod start running"
sleep 1

/tmp/pathoc -e -sc example.com:443 localhost:8080 get:/
/tmp/pathoc -e -c localhost:9999  localhost:8080 get:/p/200
/tmp/pathoc -e -c localhost:9999  localhost:8080 get:/p/200:b@100
/tmp/pathoc -n 100 -c localhost:9999  localhost:8080 get:/p/200:b@1000:c"text/json"
/tmp/pathoc -n 100 -c localhost:9999  localhost:8080 get:/p/200:b@1000:c"text/json":r
