#!/bin/bash

trap 'kill $(jobs -p) || echo "no jobs running"' EXIT
set -e
set -o xtrace

if [ ! -f ./ca/ca_certs/cert.pem ]; then
    pushd ./ca/ca_certs
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
    popd
fi
cargo build
cargo run -- mitm -p 8080 &
echo "Sleeping to let mitm wake up"
sleep 1

curl -x 127.0.0.1:8080 --cacert ./ca/ca_certs/cert.pem https://www.example.com | grep 'This domain is for use in illustrative examples in documents' && echo "Everything worked as expected" || echo "There was a problem with curl"
