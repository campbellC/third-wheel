use log::debug;
use std::fs::File;
use std::io;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{AuthorityKeyIdentifier, SubjectAlternativeName};
use openssl::x509::{GeneralNameRef, X509Name, X509NameRef, X509};

/// A certificate authority to use for impersonating websites during the
/// man-in-the-middle.
pub struct CertificateAuthority {
    /// the certificate authority's self-signed certificate
    pub(crate) cert: X509,
    /// the private signing key for the certificate authority
    pub(crate) key: PKey<Private>,
}

impl CertificateAuthority {
    pub fn load_from_pem_files(
        cert_file: &str,
        key_file: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cert_file = File::open(cert_file)?;
        let mut cert: Vec<u8> = vec![];
        io::copy(&mut cert_file, &mut cert)?;
        let cert = X509::from_pem(&cert)?;

        let mut key_file = File::open(key_file)?;
        let mut key: Vec<u8> = vec![];
        io::copy(&mut key_file, &mut key)?;
        let key = PKey::from_rsa(Rsa::private_key_from_pem(&key)?)?;

        Ok(CertificateAuthority { cert, key })
    }
}

pub(crate) fn native_identity(certificate: &X509, key: &PKey<Private>) -> native_tls::Identity {
    let pkcs = Pkcs12::builder()
        .build(&"", &"", key, certificate)
        .unwrap()
        .to_der()
        .unwrap();
    native_tls::Identity::from_pkcs12(&pkcs, &"").unwrap()
}

/// Sign a certificate for this domain
///
/// This function does not intelligently spoof fields like in the mitm proxy because
/// it does not call the actual domain to get that information. As such, this may be
/// rejected by browsers.
pub fn create_signed_certificate_for_domain(
    domain: &str,
    ca: &CertificateAuthority,
) -> Result<X509, Box<dyn std::error::Error>> {
    let mut cert_builder = X509::builder()?;

    let mut host_name = X509Name::builder()?;
    host_name.append_entry_by_text("CN", domain)?;
    let host_name = host_name.build();

    cert_builder.set_subject_name(&host_name)?;
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

fn copy_name(in_name: &X509NameRef) -> X509Name {
    let mut copy = X509Name::builder().unwrap();
    for entry in in_name.entries() {
        copy.append_entry_by_nid(
            entry.object().nid(),
            entry
                .data()
                .as_utf8()
                .expect("Expected string as entry in name")
                .as_ref(),
        )
        .expect("Failed to add entry by nid");
    }

    copy.build()
}

fn copy_alt_names(in_cert: &X509) -> Option<SubjectAlternativeName> {
    match in_cert.subject_alt_names() {
        Some(in_alt_names) => {
            let mut subject_alternative_name = SubjectAlternativeName::new();
            for gn in in_alt_names {
                if let Some(email) = gn.email() {
                    subject_alternative_name.email(email);
                } else if let Some(dns) = gn.dnsname() {
                    subject_alternative_name.dns(dns);
                } else if let Some(uri) = gn.uri() {
                    subject_alternative_name.uri(uri);
                } else if let Some(ipaddress) = gn.ipaddress() {
                    //TODO: The openssl library exposes .ipaddress -> &[u8] and the builder wants &str
                    //TODO: I have no idea whether this is u8 ascii representation of the ip or what so
                    //TODO: lets just go with it for now.
                    subject_alternative_name.ip(&String::from_utf8(ipaddress.to_vec())
                        .expect("ip address on certificate is not formatted as ascii"));
                }
            }
            Some(subject_alternative_name)
        }
        None => None,
    }
}

pub(crate) fn spoof_certificate(
    certificate: &X509,
    ca: &CertificateAuthority,
) -> Result<X509, Box<dyn std::error::Error>> {
    let mut cert_builder = X509::builder()?;

    let name: &X509NameRef = certificate.subject_name();
    let host_name = copy_name(name);
    cert_builder.set_subject_name(&host_name)?;
    cert_builder.set_not_before(certificate.not_before())?;
    cert_builder.set_not_after(certificate.not_after())?;

    cert_builder.set_serial_number(certificate.serial_number())?;

    cert_builder.set_version(2)?;

    if let Some(subject_alternative_name) = copy_alt_names(certificate) {
        let subject_alternative_name =
            subject_alternative_name.build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
        cert_builder.append_extension(subject_alternative_name)?;
    }

    // TODO: understand why these should be true or false
    // it seems from the RFC for OCSP that these should be true but this needs looking into properly
    // https://tools.ietf.org/html/rfc2560
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
    cert_builder.append_extension(authority_key_identifier)?;

    cert_builder.set_issuer_name(&ca.cert.issuer_name())?;
    cert_builder.set_pubkey(&ca.key)?;
    cert_builder.sign(&ca.key, MessageDigest::sha256())?;

    Ok(cert_builder.build())
}

#[allow(dead_code)]
fn print_certificate(certificate: &X509) {
    debug!("New certificate");

    debug!("subject_name:");
    for entry in certificate.subject_name().entries() {
        debug!("{}: {}", entry.object(), entry.data().as_utf8().unwrap());
    }
    debug!("issuer_name:");
    for entry in certificate.issuer_name().entries() {
        debug!("{}: {}", entry.object(), entry.data().as_utf8().unwrap());
    }

    debug!("subject_alt_names");
    for general_name in certificate
        .subject_alt_names()
        .unwrap_or_else(|| Stack::new().unwrap())
        .iter()
    {
        print_general_name(general_name);
    }

    debug!("issuer_alt_names");
    for general_name in certificate
        .issuer_alt_names()
        .unwrap_or_else(|| Stack::new().unwrap())
        .iter()
    {
        print_general_name(general_name);
    }

    debug!("public_key: {:?}", certificate.public_key());

    debug!("not_after: {}", certificate.not_after());
    debug!("not_before: {}", certificate.not_before());

    debug!("Signature: ");
    debug!("{:x?}", certificate.signature().as_slice());

    debug!(
        "Signature algorithm: {}",
        certificate.signature_algorithm().object()
    );

    debug!("ocsp_responders:");
    let responders = certificate.ocsp_responders();
    match responders {
        Ok(stack) => {
            for responder in stack.iter() {
                debug!("{:?}", responder);
            }
        }
        Err(err) => debug!("Responders threw error: {}", err),
    }

    let serial_number = certificate.serial_number().to_bn();
    match serial_number {
        Ok(sn) => debug!("{}", sn),
        Err(err) => debug!("Responders threw error: {}", err),
    }
}

fn print_general_name(general_name: &GeneralNameRef) {
    if let Some(email) = general_name.email() {
        debug!("email: {}", email);
    }
    if let Some(dnsname) = general_name.dnsname() {
        debug!("dnsname: {}", dnsname);
    }
    if let Some(uri) = general_name.uri() {
        debug!("uri: {}", uri);
    }
    if let Some(ipaddress) = general_name.ipaddress() {
        debug!("ipaddress: {:?}", ipaddress);
    }
}
