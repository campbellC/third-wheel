# Quick start guid
Run the script `generate_ca.sh` to generate a certificate for developing with.

To test the proxy use curl
```bash
curl --cacert ./ca/ca_certs/cert.pem -x http://127.0.0.1:8080/ https://example.com/
```

# Detailed guide to how this all works
We need a certificate authority to test mitm with while developing. Ideally this would not require overriding the OS ca list. According to [this blog](https://gist.github.com/olih/a50ce2181a657eefb041) this just means doing 

```bash
curl --cacert bla.pem https://dev.dev
```
to test this with curl. I'm sure browsers have their own set of requirements for certificate signing but this will get us off the ground. 


In order to test this we need to:
1. generate a pem file that will work as a ca - i.e. a self signed cert
3. override local /etc/hosts for that domain to my localhost
4. set up a simple https server that uses a certificate signed by that ca
5. Run curl against that server and check it is happy to trust it


# Generate a ca certificate and private key
The following generates key.pem and cert.pem which should be a self signed certificate along with the signing private key. The subject is set to some random defaults. I made this by sticking together [some](https://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl) [stackoverflow](https://stackoverflow.com/questions/21488845/how-can-i-generate-a-self-signed-certificate-with-subjectaltname-using-openssl) answers.

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com"
```
# Sign a certificate with this certificate

Since this is what third-wheel will do all the time I wrote this in Rust. This also saves us having to understand this [incredibly good answer](https://stackoverflow.com/a/21340898) on stackoverflow on how to do it from the command line utility version of openssl.

```rust
pub(crate) fn create_signed_certificate_for_domain(domain: &str, ca: &CA) -> Result<X509, Box<dyn std::error::Error>> {
    let mut cert_builder = X509::builder()?;

    let mut host_name = X509Name::builder()?;
    host_name
        .append_entry_by_text("CN", domain)?;
    let host_name = host_name.build();

    cert_builder.set_subject_name(&host_name)?;
    // TODO: why version 2 and not 3 since we use the v3 context later?
    cert_builder.set_version(2)?;
    cert_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap())?;
    cert_builder.set_not_after(&Asn1Time::days_from_now(365).unwrap())?;

    let serial_number = {
        let mut serial_number = BigNum::new()?;
        serial_number.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial_number.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;


    let subject_alternative_name = SubjectAlternativeName::new()
        .dns(domain)
        .build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
    cert_builder.append_extension(subject_alternative_name)?;

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
    cert_builder.append_extension(authority_key_identifier)?;

    cert_builder.set_issuer_name(&ca.cert.issuer_name())?;
    cert_builder.set_pubkey(&ca.key)?;
    cert_builder.sign(&ca.key, MessageDigest::sha256())?;


    Ok(cert_builder.build())
}
```

This is the loose set up for what third-wheel will do but it will copy the certificate details rather than just using the particular domain name given.


# Localhosts overriding
```bash
echo "127.0.0.1 my_test_site.com" | sudo tee -a /etc/hosts
```

# Run a simple web server
Python can very easily run a simple https web server thanks to [this stackoverflow answer](https://stackoverflow.com/questions/19705785/python-3-simple-https-server).

Firstly, we need to set up the certificate and keys in one file
```bash
cat site.pem key.pem >> localhost.pem
```
and then run the server
```bash
python3 server.py
```
where server.py contains:

```python
import http.server, ssl

server_address = ('localhost', 443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='localhost.pem',
                               ssl_version=ssl.PROTOCOL_TLSv1)
httpd.serve_forever()
```

Then in a seperate terminal we run 
```bash
curl --cacert cert.pem  https://my_test_site.com
```

And this returns the standard http request - importantly, curl accepts the certificate as valid!

