#!/usr/bin/env bash

trap 'kill $(jobs -p) || echo "no jobs running"' EXIT
set -e
set -o xtrace

CARGO_ROOT=`./find_cargo_root.sh`

if [ ! -f "$CARGO_ROOT/ca/ca_certs/cert.pem" ]; then
    pushd "$CARGO_ROOT/ca/ca_certs"
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
    popd
fi
cp -r "$CARGO_ROOT/ca/ca_certs" ./browser_containers/firefox

pushd ./browser_containers/firefox
sudo docker build . --tag firefox_testing:latest
popd

# build first to make `cargo run` happen really quickly ;)
pushd "$CARGO_ROOT"
cargo build --example trivial_mitm
cargo run --example trivial_mitm -- -p 8080 &
echo "Sleeping to let third-wheel start running"
sleep 1

sudo docker run --rm --network host firefox_testing:latest

popd
