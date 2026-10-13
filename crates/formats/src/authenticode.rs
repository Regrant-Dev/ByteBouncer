//! Authenticode signature parsing for PE files (SPEC §5.2.1: embedded
//! signatures are reported with signer identity and validity).
//!
//! [`inspect`] reads the PE certificate table, decodes the PKCS#7
//! `SignedData`, reports the signer and certificates, and recomputes the
//! Authenticode image digest to compare against the signed
//! `SpcIndirectDataContent` digest. That comparison is an integrity check
//! only: it shows whether the bytes were changed after signing.
//!
//! **Not done:** chain-of-trust validation against any root store, revocation
//! checks, timestamp validation, and cryptographic verification of the
//! `SignerInfo` signature itself. A matching digest therefore proves nothing
//! about who signed the file; the reported subject is an unverified claim.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Reader, SliceReader, Tag, Tagged};
use sha2::Digest;
use x509_cert::Certificate;
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::util::{slice, u16le, u32le};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_NESTED_SIGNATURE: &str = "1.3.6.1.4.1.311.2.4.1";
const OID_RFC3161_TIMESTAMP: &str = "1.3.6.1.4.1.311.3.3.1";
const OID_COUNTER_SIGNATURE: &str = "1.2.840.113549.1.9.6";
const OID_SKI: &str = "2.5.29.14";
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// What was found in a PE file's Authenticode signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticodeInfo {
    /// A certificate table with a PKCS#7 signature is present.
    pub present: bool,
    /// RFC 4514 subject of the certificate matching the signer (unverified).
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// Image digest algorithm named in `SpcIndirectDataContent`.
    pub digest_algorithm: Option<String>,
    pub signed_digest_hex: Option<String>,
    pub computed_digest_hex: Option<String>,
    /// `Some(true)` if the recomputed image digest equals the signed one;
    /// `None` when either digest is unavailable.
    pub digest_matches: Option<bool>,
    /// Subjects of every certificate embedded in the signature.
    pub certificates: Vec<String>,
    /// An RFC 3161 timestamp or PKCS#9 counter-signature is attached.
    pub timestamped: bool,
    /// Additional (nested) signatures attached to the primary one.
    pub nested_signatures: usize,
    pub problems: Vec<String>,
}

/// Layout facts needed to locate the signature and hash the image.
struct PeLayout {
    checksum_off: usize,
    cert_dir_off: usize,
    cert_off: usize,
    cert_len: usize,
}

fn pe_layout(pe: &[u8]) -> Result<Option<PeLayout>, String> {
    if !pe.starts_with(b"MZ") {
        return Err("not a PE file (no MZ header)".into());
    }
    let nt = u32le(pe, 0x3C).ok_or("truncated DOS header")? as usize;
    if slice(pe, nt, 4) != Some(b"PE\0\0") {
        return Err("not a PE file (no PE signature)".into());
    }
    let opt = nt + 24;
    let dirs = match u16le(pe, opt).ok_or("truncated optional header")? {
        0x10b => opt + 96,
        0x20b => opt + 112,
        m => return Err(format!("unknown optional header magic {m:#x}")),
    };
    let count = u32le(pe, dirs - 4).ok_or("truncated optional header")?;
    let cert_dir_off = dirs + 4 * 8;
    if count <= 4 || slice(pe, cert_dir_off, 8).is_none() {
        return Ok(None);
    }
    let cert_off = u32le(pe, cert_dir_off).unwrap_or(0) as usize;
    let cert_len = u32le(pe, cert_dir_off + 4).unwrap_or(0) as usize;
    if cert_off == 0 && cert_len == 0 {
        return Ok(None);
    }
    Ok(Some(PeLayout {
        checksum_off: opt + 64,
        cert_dir_off,
        cert_off,
        cert_len,
    }))
}

/// Inspect the Authenticode signature of `pe`. Never panics; anything odd is
/// reported in [`AuthenticodeInfo::problems`].
pub fn inspect(pe: &[u8]) -> AuthenticodeInfo {
    let mut info = AuthenticodeInfo::default();
    let layout = match pe_layout(pe) {
        Ok(Some(l)) => l,
        Ok(None) => {
            info.problems.push("no certificate table (unsigned)".into());
            return info;
        }
        Err(e) => {
            info.problems.push(e);
            return info;
        }
    };
    let Some(table) = slice(pe, layout.cert_off, layout.cert_len) else {
        info.problems.push(format!(
            "certificate table ({} bytes at {:#x}) lies outside the file",
            layout.cert_len, layout.cert_off
        ));
        return info;
    };
    if layout.cert_off < layout.cert_dir_off + 8 {
        info.problems
            .push("certificate table overlaps the PE headers".into());
        return info;
    }
    if layout.cert_off + layout.cert_len != pe.len() {
        info.problems
            .push("data follows the certificate table (unhashed appended data)".into());
    }

    let mut signed = None;
    let mut off = 0usize;
    while off + 8 <= table.len() {
        let len = u32le(table, off).unwrap_or(0) as usize;
        let kind = u16le(table, off + 6).unwrap_or(0);
        if len < 8 || off + len > table.len() {
            info.problems
                .push(format!("malformed WIN_CERTIFICATE at table offset {off}"));
            break;
        }
        if kind == WIN_CERT_TYPE_PKCS_SIGNED_DATA && signed.is_none() {
            signed = Some(&table[off + 8..off + len]);
        } else {
            info.problems.push(format!(
                "additional WIN_CERTIFICATE entry of type {kind:#06x} ignored"
            ));
        }
        off += len.next_multiple_of(8);
    }
    let Some(blob) = signed else {
        info.problems
            .push("no PKCS#7 signed-data certificate entry".into());
        return info;
    };
    info.present = true;
    if let Err(e) = parse_signature(blob, &mut info) {
        info.problems
            .push(format!("signature could not be decoded: {e}"));
    }
    if let Some(alg) = info.digest_algorithm.clone() {
        match image_digest(pe, &layout, &alg) {
            Some(d) => {
                let d = hex::encode(d);
                info.digest_matches = info.signed_digest_hex.as_ref().map(|s| *s == d);
                info.computed_digest_hex = Some(d);
            }
            None => info
                .problems
                .push(format!("image digest algorithm {alg} is not supported")),
        }
    }
    if info.digest_matches == Some(false) {
        info.problems.push(
            "image digest does not match the signed digest (file modified after signing)".into(),
        );
    }
    info
}

/// Decode the first DER element of `blob`, ignoring trailing padding.
fn decode_prefix<'a, T: Decode<'a>>(blob: &'a [u8]) -> der::Result<T> {
    let mut reader = SliceReader::new(blob)?;
    T::decode(&mut reader)
}

fn parse_signature(blob: &[u8], info: &mut AuthenticodeInfo) -> der::Result<()> {
    let ci: ContentInfo = decode_prefix(blob)?;
    if ci.content_type.to_string() != OID_SIGNED_DATA {
        info.problems.push(format!(
            "unexpected PKCS#7 content type {}",
            ci.content_type
        ));
        return Ok(());
    }
    let sd: SignedData = ci.content.decode_as()?;
    let certs: Vec<&Certificate> = sd
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    info.certificates = certs
        .iter()
        .map(|c| c.tbs_certificate.subject.to_string())
        .collect();

    let eci = &sd.encap_content_info;
    if eci.econtent_type.to_string() != OID_SPC_INDIRECT_DATA {
        info.problems.push(format!(
            "signed content is {} rather than SpcIndirectDataContent",
            eci.econtent_type
        ));
    } else if let Some(content) = &eci.econtent {
        match spc_digest(content) {
            Ok((alg, digest)) => {
                info.digest_algorithm = Some(digest_name(&alg.oid));
                info.signed_digest_hex = Some(hex::encode(digest));
            }
            Err(e) => info
                .problems
                .push(format!("SpcIndirectDataContent could not be decoded: {e}")),
        }
    } else {
        info.problems.push("signature has no signed content".into());
    }

    let signers = sd.signer_infos.0.as_slice();
    if signers.len() != 1 {
        info.problems
            .push(format!("expected one SignerInfo, found {}", signers.len()));
    }
    if let Some(si) = signers.first() {
        let signer = certs.iter().find(|c| matches_sid(c, &si.sid));
        match signer {
            Some(c) => {
                let tbs = &c.tbs_certificate;
                info.signer_subject = Some(tbs.subject.to_string());
                info.signer_issuer = Some(tbs.issuer.to_string());
                info.not_before = Some(tbs.validity.not_before.to_string());
                info.not_after = Some(tbs.validity.not_after.to_string());
            }
            None => {
                if let SignerIdentifier::IssuerAndSerialNumber(ias) = &si.sid {
                    info.signer_issuer = Some(ias.issuer.to_string());
                }
                info.problems
                    .push("signer certificate is not embedded in the signature".into());
            }
        }
        for attr in si.unsigned_attrs.iter().flat_map(|a| a.iter()) {
            match attr.oid.to_string().as_str() {
                OID_NESTED_SIGNATURE => info.nested_signatures += attr.values.len(),
                OID_RFC3161_TIMESTAMP | OID_COUNTER_SIGNATURE => info.timestamped = true,
                _ => {}
            }
        }
    }
    Ok(())
}

/// Extract the DigestInfo from `SpcIndirectDataContent`. Authenticode embeds
/// the SEQUENCE directly; CMS-style producers wrap it in an OCTET STRING, so
/// accept both.
fn spc_digest(content: &Any) -> der::Result<(AlgorithmIdentifierOwned, Vec<u8>)> {
    let der = if content.tag() == Tag::OctetString {
        content.value().to_vec()
    } else {
        content.to_der()?
    };
    let spc = Any::from_der(&der)?;
    spc.sequence(|r| {
        let _data: Any = r.decode()?;
        r.sequence(|r| {
            let alg: AlgorithmIdentifierOwned = r.decode()?;
            let digest: OctetString = r.decode()?;
            Ok((alg, digest.into_bytes()))
        })
    })
}

fn matches_sid(cert: &Certificate, sid: &SignerIdentifier) -> bool {
    let tbs = &cert.tbs_certificate;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            tbs.issuer == ias.issuer && tbs.serial_number == ias.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => tbs
            .extensions
            .iter()
            .flatten()
            .filter(|e| e.extn_id.to_string() == OID_SKI)
            .any(|e| {
                OctetString::from_der(e.extn_value.as_bytes())
                    .is_ok_and(|v| v.as_bytes() == ski.0.as_bytes())
            }),
    }
}

fn digest_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.3.14.3.2.26" => "sha1".into(),
        "2.16.840.1.101.3.4.2.1" => "sha256".into(),
        "2.16.840.1.101.3.4.2.2" => "sha384".into(),
        "2.16.840.1.101.3.4.2.3" => "sha512".into(),
        "1.2.840.113549.2.5" => "md5".into(),
        other => other.into(),
    }
}

/// The Authenticode image hash, simplified: every byte of the file except the
/// CheckSum field, the certificate-table directory entry, and the certificate
/// table itself, in file order. This equals the specified algorithm (headers,
/// then sections sorted by file offset, then trailing data) whenever sections
/// are laid out contiguously in file order, which is what linkers and signing
/// tools produce; exotic layouts with gaps or overlapping sections may
/// produce a spurious mismatch.
fn image_digest(pe: &[u8], l: &PeLayout, alg: &str) -> Option<Vec<u8>> {
    let ranges = [
        0..l.checksum_off,
        l.checksum_off + 4..l.cert_dir_off,
        l.cert_dir_off + 8..l.cert_off,
        l.cert_off + l.cert_len..pe.len(),
    ];
    fn run<D: Digest>(pe: &[u8], ranges: &[std::ops::Range<usize>]) -> Option<Vec<u8>> {
        let mut d = D::new();
        for r in ranges {
            d.update(pe.get(r.clone())?);
        }
        Some(d.finalize().to_vec())
    }
    match alg {
        "sha1" => run::<sha1::Sha1>(pe, &ranges),
        "sha256" => run::<sha2::Sha256>(pe, &ranges),
        "sha384" => run::<sha2::Sha384>(pe, &ranges),
        "sha512" => run::<sha2::Sha512>(pe, &ranges),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-made PE32+ signed with a throwaway self-signed certificate
    /// (generated with openssl; no third-party code).
    const SIGNED: &[u8] = include_bytes!("../tests/fixtures/authenticode-selfsigned.exe");

    #[test]
    fn signed_fixture_matches() {
        let info = inspect(SIGNED);
        assert!(info.present, "{:?}", info.problems);
        assert_eq!(info.digest_algorithm.as_deref(), Some("sha256"));
        assert_eq!(info.digest_matches, Some(true), "{:?}", info);
        assert!(
            info.signer_subject
                .as_deref()
                .unwrap()
                .contains("ByteBouncer Test Signer")
        );
        assert_eq!(info.signer_subject, info.signer_issuer);
        assert_eq!(info.certificates.len(), 1);
        assert!(info.not_before.is_some() && info.not_after.is_some());
    }

    #[test]
    fn tampered_byte_breaks_digest() {
        let mut pe = SIGNED.to_vec();
        pe[0x300] ^= 0xFF;
        let info = inspect(&pe);
        assert!(info.present);
        assert_eq!(info.digest_matches, Some(false));
        assert!(info.problems.iter().any(|p| p.contains("does not match")));
    }

    #[test]
    fn checksum_change_does_not_break_digest() {
        let mut pe = SIGNED.to_vec();
        let opt = u32le(&pe, 0x3C).unwrap() as usize + 24;
        pe[opt + 64] ^= 0xFF;
        assert_eq!(inspect(&pe).digest_matches, Some(true));
    }

    fn unsigned() -> Vec<u8> {
        let mut pe = SIGNED.to_vec();
        let l = pe_layout(&pe).unwrap().unwrap();
        pe.truncate(l.cert_off);
        pe[l.cert_dir_off..l.cert_dir_off + 8].fill(0);
        pe
    }

    #[test]
    fn unsigned_and_non_pe() {
        let info = inspect(&unsigned());
        assert!(!info.present);
        assert!(info.problems[0].contains("unsigned"));
        let info = inspect(b"\x7fELF not a pe");
        assert!(!info.present);
        assert!(!info.problems.is_empty());
    }

    #[test]
    fn garbage_cert_table_reports_problems() {
        let mut pe = unsigned();
        let l = pe_layout(SIGNED).unwrap().unwrap();
        let off = pe.len() as u32;
        let mut entry = 24u32.to_le_bytes().to_vec();
        entry.extend_from_slice(&[0, 2, 2, 0]);
        entry.extend_from_slice(&[
            0x30, 0x82, 0xFF, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ]);
        pe.extend_from_slice(&entry);
        pe[l.cert_dir_off..l.cert_dir_off + 4].copy_from_slice(&off.to_le_bytes());
        pe[l.cert_dir_off + 4..l.cert_dir_off + 8].copy_from_slice(&24u32.to_le_bytes());
        let info = inspect(&pe);
        assert!(info.present);
        assert!(
            info.problems
                .iter()
                .any(|p| p.contains("could not be decoded"))
        );
        // Directory pointing outside the file.
        pe[l.cert_dir_off + 4..l.cert_dir_off + 8].copy_from_slice(&0xFFFFu32.to_le_bytes());
        assert!(inspect(&pe).problems[0].contains("outside"));
    }

    #[test]
    fn truncations_and_corruption_never_panic() {
        for n in 0..SIGNED.len() {
            let _ = inspect(&SIGNED[..n]);
        }
        let l = pe_layout(SIGNED).unwrap().unwrap();
        for i in (l.cert_off..SIGNED.len()).step_by(7) {
            let mut pe = SIGNED.to_vec();
            pe[i] = pe[i].wrapping_add(0x41);
            let _ = inspect(&pe);
        }
    }

    /// Validate against a real signed PE: `BYTEBOUNCER_SIGNED_PE=path cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn real_signed_pe() {
        let path = std::env::var("BYTEBOUNCER_SIGNED_PE").expect("set BYTEBOUNCER_SIGNED_PE");
        let info = inspect(&std::fs::read(path).unwrap());
        eprintln!("{info:#?}");
        assert!(info.present);
        assert_eq!(info.digest_matches, Some(true));
        assert!(info.signer_subject.is_some());
    }
}
