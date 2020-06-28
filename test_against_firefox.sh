#!/bin/bash

trap 'kill $(jobs -p) || echo "no jobs running"' EXIT
set -e
set -o xtrace

if [ ! -f ./ca/ca_certs/cert.pem ]; then
    pushd ./ca/ca_certs
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
    popd
fi
cp -r ./ca/ca_certs ./testing_against_browsers/firefox

pushd ./testing_against_browsers/firefox
sudo docker build . --tag firefox_testing:latest
popd

# build first to make `cargo run` happen really quickly ;)
cargo build
cargo run -- mitm -p 8080 &
echo "Sleeping to let third-wheel start running"
sleep 1

sudo docker run --rm --network host firefox_testing:latest
