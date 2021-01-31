#!/bin/bash

trap 'kill $(jobs -p)' EXIT
set -e
set -o xtrace

pushd ./ca/ca_certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -passout pass:"third-wheel" -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
popd
cargo run --example sign_cert_for_site -- my_test_site.com -o ca/simple_server/localhost.pem
cat ca/ca_certs/key.pem >> ca/simple_server/localhost.pem
pushd ./ca/simple_server
python3 server.py <(echo "third-wheel") &
echo "Sleeping to let python server wake up"
sleep 1
popd
expected="/tmp/curl_test"
echo "<html><head><title>Environment Test</title></head></html>" >$expected
actual="/tmp/curl_output_test"
curl --cacert ./ca/ca_certs/cert.pem --resolve my_test_site.com:4443:127.0.0.1 https://my_test_site.com:4443 >$actual
echo "Testing curl output"
cmp $expected $actual && echo "Everything worked, your environment is looking good" || echo "Curl received output that was different than expected, something is wrong"
