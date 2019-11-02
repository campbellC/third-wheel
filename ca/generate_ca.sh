#!/bin/bash
pushd ca_certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
popd
