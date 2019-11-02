use std::fs::File;
use std::io;

use openssl::x509::{X509, X509Name};
use openssl::asn1::Asn1Time;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::bn::{BigNum, MsbOption};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::extension::AuthorityKeyIdentifier;

pub struct CA {
    pub(self) cert: X509,
    pub(self) key: PKey<Private>,
}

impl CA {
    pub fn load_from_pem_files(cert_file: &str, key_file: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cert_file = File::open(cert_file)?;
        let mut cert: Vec<u8> = vec![];
        io::copy(&mut cert_file, &mut cert)?;
        let cert = X509::from_pem(&cert)?;

        let mut key_file = File::open(key_file)?;
        let mut key: Vec<u8> = vec![];
        io::copy(&mut key_file, &mut key)?;
        let key = PKey::from_rsa(Rsa::private_key_from_pem(&key)?)?;

        Ok(CA { cert, key })
    }
}


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