#!/usr/bin/env bash

trap 'kill $(jobs -p) || echo "no jobs running"' EXIT
set -ueox pipefail


CARGO_ROOT=`./find_cargo_root.sh`

pushd ./pathod_docker
sudo docker build . --tag pathod:latest
popd

pushd "$CARGO_ROOT"
cargo build --example trivial_mitm
RUST_BACKTRACE=1 cargo run --example trivial_mitm -- -p 8080 &
echo "Sleeping to let mitm wake up"
sleep 1
popd

sudo docker run --rm --network host pathod:latest
