use argh::FromArgs;
use std::fs::File;
use std::io::Write;

use third_wheel::*;

fn run_sign_certificate_for_domain(
    outfile: &str,
    cert_file: &str,
    key_file: &str,
    domain: &str,
) -> Result<(), Error> {
    let ca = CertificateAuthority::load_from_pem_files(cert_file, key_file)?;
    let site_cert = create_signed_certificate_for_domain(domain, &ca)?;

    let mut site_cert_file = File::create(outfile)?;
    site_cert_file.write_all(&site_cert.to_pem()?)?;
    Ok(())
}

/// Sign a x509 v2 certificate for a given domain and save it out to a file
#[derive(FromArgs)]
struct SignRequest {
    /// domain to sign the certificate for
    #[argh(positional)]
    domain: String,

    /// file to store the certificate in
    #[argh(option, short = 'o', default = "\"site.pem\".to_string()")]
    outfile: String,

    /// pem file containing the ca certificate
    #[argh(
        option,
        short = 'c',
        default = "\"./ca/ca_certs/cert.pem\".to_string()"
    )]
    ca_cert_file: String,

    /// pem file containing ca key
    #[argh(option, short = 'k', default = "\"./ca/ca_certs/key.pem\".to_string()")]
    ca_key_file: String,
}

fn main() -> Result<(), Error> {
    let up: SignRequest = argh::from_env();
    run_sign_certificate_for_domain(&up.outfile, &up.ca_cert_file, &up.ca_key_file, &up.domain)
}
