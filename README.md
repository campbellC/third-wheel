### third-wheel
third-wheel is a TLS man-in-the-middle proxy written in rust, with the aim of being lightweight and fast. It is currently in pre-alpha stage.

### Usage
third-wheel is a library so you can modify it's behaviour in order to capture traffic, or modify it en route. It also comes with some binaries which can be found in `src/bin`. These require the `binaries` feature to be switched on. FOr example, `trivial_mitm` simply proxies the traffic but does not do anything to it, you can run with `cargo run`. For example:
```
cargo run --features binaries --bin trivial_mitm -- -h
```
will give you some hints. If you just want a TLS mitm proxy:
```
cargo run --features binaries --bin trivial_mitm -- -p 8080
```
will get it running on port 8080.

To test you can run curl against it with
```
curl -x http://127.0.0.1:8080 https://google.com -vv --http1.1 --cacert ./ca/ca_certs/cert.pem -L
```
from the third-wheel directory. You'll need to have run `set_up_and_validate_environment.sh` first as the root certificates are not generated on the fly yet.

#### Development
If you want to develop/use third-wheel while still in early stages you will need to generate the certificate authority certificates and check your local version of curl and openssl are working as expected. Run the `set_up_and_validate_environment.sh` script to do this.

#### Testing against Chrome and Firefox
The `test_against_chrome.sh` and `test_against_firefox.sh` scripts uses Docker, (Chromium|Firefox) and Selenium to test that the browsers are tricked by the mitm. It does most of the setup for you but you do need docker installed for it to work. It uses sudo to run docker because it doesn't assume you've modified the docker group - if you have done so feel free to delete the sudo's and then feel more confident running the script :)

#### Planned Features
* ~~Transparent HTTP Proxy~~
* Transparent HTTPS Proxy
* ~~MITM Proxy trusted by standard curl~~
* ~~MITM Proxy trusted by Chrome~~
* ~~MITM Proxy trusted by Firefox~~
* MITM Proxy mode is faster/slimmer in memory than [mitmproxy](https://github.com/mitmproxy/mitmproxy)
* ~~Library version for extension by other developers~~
