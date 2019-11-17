### third-wheel
third-wheel is a TLS man-in-the-middle proxy written in rust, with the aim of being lightweight and fast. It is currently in pre-alpha stage.

### Usage
```
cargo run -- -h
``` 
will give you some hints. If you just want a TLS mitm proxy:
```
cargo run -- mitm -p 8080
``` 
will get it running.

#### Development
If you want to develop/use third-wheel while still in early stages you will need to generate the certificate authority certificates and check your local version of curl and openssl are working as expected. Run the `set_up_and_validate_environment.sh` script to do this.

#### Planned Features
* ~~Transparent HTTP Proxy~~
* Transparent HTTPS Proxy
* ~~MITM Proxy trusted by standard curl~~
* MITM Proxy trusted by Chrome & Firefox
* MITM Proxy mode is faster/slimmer in memory than [mitmproxy](https://github.com/mitmproxy/mitmproxy)
* Library version for extension by other developers

