#!/bin/bash

trap 'kill $(jobs -p)' EXIT
set -e
set -o xtrace

pushd ./ca/ca_certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
popd
cargo run --bin=third-wheel -- sign-cert-for-domain my_test_site.com -o ca/simple_server/localhost.pem
cat ca/ca_certs/key.pem >> ca/simple_server/localhost.pem
pushd ./ca/simple_server
python3 server.py &
echo "Sleeping to let python server wake up"
sleep 1
popd
expected="/tmp/curl_test"
cat >$expected <<EOF
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href="localhost.pem">localhost.pem</a></li>
<li><a href="server.py">server.py</a></li>
</ul>
<hr>
</body>
</html>
EOF
actual="/tmp/curl_output_test"
curl --cacert ./ca/ca_certs/cert.pem --resolve my_test_site.com:4443:127.0.0.1 https://my_test_site.com:4443 >$actual
echo "Testing curl output"
cmp --silent $expected $actual && echo "Everything worked, your environment is looking good" || echo "Curl received output that was different than expected, something is wrong"
