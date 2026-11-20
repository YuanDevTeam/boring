#![cfg(feature = "client-fingerprint")]
//! Closed-template wire observations through the production connector. No sockets.
use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector, SslMethod, SslVersion};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};

#[derive(Debug, Default)]
struct Capture(Vec<u8>);
impl Read for Capture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}
impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (out, rest) = input.split_at(n);
    *input = rest;
    out
}
fn vector<'a>(input: &mut &'a [u8], width: usize) -> &'a [u8] {
    let n = take(input, width)
        .iter()
        .fold(0usize, |n, b| n * 256 + usize::from(*b));
    take(input, n)
}
fn codes(input: &[u8]) -> Vec<u16> {
    assert_eq!(input.len() % 2, 0);
    input
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect()
}
fn grease(id: u16) -> bool {
    id & 0x0f0f == 0x0a0a && id >> 8 == id & 0xff
}

fn check_ios() {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Ios14).unwrap();
    for _ in 0..8 {
        let error = connector
            .configure(b"\x02h2\x08http/1.1")
            .unwrap()
            .connect("fingerprint.test", Capture::default())
            .unwrap_err();
        let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
            panic!("expected hello");
        };
        let mut record = stream.get_ref().0.as_slice();
        assert_eq!(take(&mut record, 3), &[22, 3, 1]);
        let mut hello = vector(&mut record, 2);
        assert!(record.is_empty());
        assert_eq!(take(&mut hello, 1), &[1]);
        let mut body = vector(&mut hello, 3);
        assert!(hello.is_empty());
        assert_eq!(take(&mut body, 2), &[3, 3]);
        take(&mut body, 32);
        assert_eq!(vector(&mut body, 1).len(), 32);
        let ciphers = codes(vector(&mut body, 2));
        assert!(grease(ciphers[0]));
        assert_eq!(
            &ciphers[1..],
            &[
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024,
                0xc023, 0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d,
                0x003c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a
            ]
        );
        assert_eq!(vector(&mut body, 1), &[0]);
        let mut ext = vector(&mut body, 2);
        assert!(body.is_empty());
        let mut rows = vec![];
        while !ext.is_empty() {
            let kind = codes(take(&mut ext, 2))[0];
            rows.push((kind, vector(&mut ext, 2)));
        }
        assert!(grease(rows[0].0));
        assert!(rows[0].1.is_empty());
        let last = rows.len() - 1 - usize::from(rows.last().unwrap().0 == 21);
        assert!(grease(rows[last].0));
        assert_eq!(rows[last].1, &[0]);
        assert_eq!(
            rows[1..last].iter().map(|r| r.0).collect::<Vec<_>>(),
            [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43]
        );
        let value = |id| rows.iter().find(|r| r.0 == id).unwrap().1;
        assert_eq!(&value(0)[5..], b"fingerprint.test");
        assert_eq!(value(16), b"\0\x0c\x02h2\x08http/1.1");
        assert!(!rows.iter().any(|r| r.0 == 27 || r.0 == 35));
        assert_eq!(
            codes(&value(13)[2..]),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201
            ]
        );
        assert_eq!(&value(43)[3..], &[3, 4, 3, 3]); // Approved TLS1.2 floor.
        let groups = codes(&value(10)[2..]);
        assert!(grease(groups[0]));
        assert_eq!(&groups[1..], &[29, 23, 24, 25]);
        let mut shares = &value(51)[2..];
        for (id, size) in [(groups[0], 1), (29, 32)] {
            assert_eq!(codes(take(&mut shares, 2)), [id]);
            assert_eq!(vector(&mut shares, 2).len(), size);
        }
        assert!(shares.is_empty());
        for (id, expected) in [
            (23, &[][..]),
            (65281, &[0]),
            (11, &[1, 0]),
            (5, &[1, 0, 0, 0, 0]),
            (18, &[]),
            (45, &[1, 1]),
        ] {
            assert_eq!(value(id), expected);
        }
        let padding = value(21);
        let unpadded = stream.get_ref().0.len() - 5 - padding.len() - 4;
        assert!((256..512).contains(&unpadded));
        assert_eq!(padding.len(), 512 - unpadded - 4);
        assert!(padding.iter().all(|b| *b == 0));
    }
}

#[test]
fn ios14_preserves_its_independent_cipher_and_extension_vectors() {
    check_ios();
}

#[test]
fn ios_rsa_sha256_cipher_is_excluded_from_the_default_offer() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let error = connector
        .configure()
        .unwrap()
        .connect("fingerprint.test", Capture::default())
        .unwrap_err();
    let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
        panic!("expected hello");
    };
    let mut record = stream.get_ref().0.as_slice();
    take(&mut record, 3);
    let mut hello = vector(&mut record, 2);
    take(&mut hello, 4);
    take(&mut hello, 34);
    vector(&mut hello, 1);
    assert!(!codes(vector(&mut hello, 2)).contains(&0x003c));
}

fn profile_fields(profile: ClientFingerprint) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
    profile_fields_with_settings(profile, true, SslVersion::TLS1_2)
}

fn profile_fields_with_settings(
    profile: ClientFingerprint,
    application_settings: bool,
    min_version: SslVersion,
) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_min_proto_version(Some(min_version)).unwrap();
    let connector = FingerprintConnector::new(builder, profile).unwrap();
    let error = connector
        .configure_with_application_settings(b"\x02h2\x08http/1.1", application_settings)
        .unwrap()
        .connect("fingerprint.test", Capture::default())
        .unwrap_err();
    let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
        panic!("expected hello");
    };
    let mut record = stream.get_ref().0.as_slice();
    take(&mut record, 3);
    let mut hello = vector(&mut record, 2);
    take(&mut hello, 4);
    take(&mut hello, 34);
    vector(&mut hello, 1);
    let ciphers = codes(vector(&mut hello, 2));
    vector(&mut hello, 1);
    let mut extensions = vector(&mut hello, 2);
    let mut rows = Vec::new();
    while !extensions.is_empty() {
        let kind = codes(take(&mut extensions, 2))[0];
        rows.push((kind, vector(&mut extensions, 2).to_vec()));
    }
    (ciphers, rows)
}

fn key_shares(mut extension: &[u8]) -> Vec<(u16, &[u8])> {
    let mut encoded = vector(&mut extension, 2);
    assert!(extension.is_empty());
    let mut shares = Vec::new();
    while !encoded.is_empty() {
        let group = codes(take(&mut encoded, 2))[0];
        shares.push((group, vector(&mut encoded, 2)));
    }
    shares
}

#[test]
fn chrome155_advertises_native_signatures_and_the_captured_trust_anchor_list() {
    let (ciphers, extensions) = profile_fields(ClientFingerprint::Chrome155);
    assert!(grease(ciphers[0]));
    assert_eq!(
        ciphers[1..],
        [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ]
    );
    let mut kinds: Vec<_> = extensions
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| !grease(*kind))
        .collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 0xca34, 65037, 65281]
    );
    let value = |id| {
        extensions
            .iter()
            .find(|(kind, _)| *kind == id)
            .unwrap()
            .1
            .as_slice()
    };
    assert_eq!(value(17613), b"\0\x03\x02h2");
    let signatures = codes(&value(13)[2..]);
    assert!(grease(signatures[0]));
    assert_eq!(
        signatures[1..],
        [0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    );
    let anchors = value(0xca34);
    assert_eq!(anchors.len(), 186);
    // SHA-256 of the extension body in the independent Chrome 155 capture.
    assert_eq!(
        hex::encode(boring::sha::sha256(anchors)),
        "734236b257e52e7d202b222a0694fedf187c12b11a4fcc733dd00f3331b7f16c"
    );
    let shares = key_shares(value(51));
    assert!(grease(shares[0].0));
    assert_eq!(shares[0].1, &[0]);
    assert_eq!((shares[1].0, shares[1].1.len()), (4588, 1216));
    assert_eq!((shares[2].0, shares[2].1.len()), (29, 32));
    assert_ne!(&shares[1].1[1184..], shares[2].1);
    assert_eq!(shares.len(), 3);
}

#[test]
fn firefox148_reuses_the_x25519_key_and_offers_ordered_certificate_compression() {
    let (ciphers, extensions) = profile_fields(ClientFingerprint::Firefox148);
    assert_eq!(
        ciphers,
        [
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
        ]
    );
    assert_eq!(
        extensions.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        [0, 23, 65281, 10, 11, 16, 5, 34, 18, 51, 43, 13, 28, 27, 65037]
    );
    let value = |id| {
        extensions
            .iter()
            .find(|(kind, _)| *kind == id)
            .unwrap()
            .1
            .as_slice()
    };
    assert_eq!(value(27), &[6, 0, 1, 0, 2, 0, 3]);
    assert_eq!(codes(&value(10)[2..]), [4588, 29, 23, 24, 25, 256, 257]);
    let shares = key_shares(value(51));
    assert_eq!(
        shares
            .iter()
            .map(|(group, bytes)| (*group, bytes.len()))
            .collect::<Vec<_>>(),
        [(4588, 1216), (29, 32), (23, 65)]
    );
    assert_eq!(&shares[0].1[1184..], shares[1].1);
}

#[test]
fn safari263_preserves_its_fixed_order_and_independent_hybrid_share() {
    let (ciphers, extensions) = profile_fields(ClientFingerprint::Safari263);
    assert!(grease(ciphers[0]));
    assert_eq!(
        ciphers[1..],
        [
            0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009,
            0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a
        ]
    );
    let kinds: Vec<_> = extensions.iter().map(|(kind, _)| *kind).collect();
    assert!(grease(kinds[0]));
    assert!(grease(*kinds.last().unwrap()));
    assert_eq!(
        kinds[1..kinds.len() - 1],
        [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]
    );
    let value = |id| {
        extensions
            .iter()
            .find(|(kind, _)| *kind == id)
            .unwrap()
            .1
            .as_slice()
    };
    assert_eq!(value(27), &[2, 0, 1]);
    assert_eq!(
        codes(&value(13)[2..]),
        [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
    );
    let shares = key_shares(value(51));
    assert!(grease(shares[0].0));
    assert_eq!(shares[0].1, &[0]);
    assert_eq!((shares[1].0, shares[1].1.len()), (4588, 1216));
    assert_eq!((shares[2].0, shares[2].1.len()), (29, 32));
    assert_ne!(&shares[1].1[1184..], shares[2].1);
    assert_eq!(shares.len(), 3);
}

#[test]
fn recent_profiles_require_tls12_and_keep_the_callers_tls13_floor() {
    for profile in [
        ClientFingerprint::Chrome155,
        ClientFingerprint::Firefox148,
        ClientFingerprint::Safari263,
    ] {
        for (requested, expected) in [
            (SslVersion::TLS1_1, &[0x0304, 0x0303][..]),
            (SslVersion::TLS1_3, &[0x0304][..]),
        ] {
            let (_, extensions) = profile_fields_with_settings(profile, true, requested);
            let versions = &extensions.iter().find(|(kind, _)| *kind == 43).unwrap().1;
            assert_eq!(
                codes(&versions[1..])
                    .into_iter()
                    .filter(|id| !grease(*id))
                    .collect::<Vec<_>>(),
                expected,
                "{profile:?} with {requested:?}"
            );
        }
    }
}

#[test]
fn removed_native_profile_ids_are_rejected_on_fresh_clients() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    for id in [2, 3, 4] {
        let config = connector.configure().unwrap();
        assert_eq!(
            unsafe { boring_sys::SSL_set_client_fingerprint(config.as_ptr(), id) },
            0,
            "obsolete native profile ID {id}"
        );
        assert!(!boring::error::ErrorStack::get().errors().is_empty());
    }
}

#[test]
fn android11_keeps_okhttp_order_without_adding_tls13_or_browser_extensions() {
    let (ciphers, extensions) = profile_fields(ClientFingerprint::Android11);
    assert_eq!(
        ciphers,
        [
            0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
            0x0035,
        ]
    );
    let ids: Vec<_> = extensions.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(&ids[..7], [0, 23, 65281, 10, 11, 5, 13]);
    assert!(ids.contains(&16)); // Transport-owned ALPN is retained.
    assert!(
        !ids.iter()
            .any(|id| grease(*id) || matches!(id, 27 | 35 | 43 | 51 | 65037)),
        "unexpected Android11 extension vector: {ids:?}"
    );
}

#[test]
fn tls12_profiles_preserve_stricter_caller_version_limits() {
    for profile in [
        ClientFingerprint::Android11,
        ClientFingerprint::ThreeSixty75,
    ] {
        for maximum in [SslVersion::TLS1, SslVersion::TLS1_1] {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
            builder.set_max_proto_version(Some(maximum)).unwrap();
            let connector = FingerprintConnector::new(builder, profile).unwrap();
            let config = connector.configure(b"").unwrap();
            assert_eq!(config.max_proto_version(), Some(maximum), "{profile:?}");
            let error = config
                .connect("fingerprint.test", Capture::default())
                .unwrap_err();
            let boring::ssl::HandshakeError::Failure(stream) = error else {
                panic!("a conflicting version range must fail before sending a hello");
            };
            assert!(stream.get_ref().0.is_empty());
        }
    }
}

#[test]
fn tls12_profiles_keep_their_ceiling_without_lowering_the_callers_minimum() {
    for profile in [
        ClientFingerprint::Android11,
        ClientFingerprint::ThreeSixty75,
    ] {
        for maximum in [None, Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_3)] {
            for minimum in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
                let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
                builder.set_min_proto_version(Some(minimum)).unwrap();
                builder.set_max_proto_version(maximum).unwrap();
                let connector = FingerprintConnector::new(builder, profile).unwrap();
                let mut config = connector.configure(b"").unwrap();
                assert_eq!(config.min_proto_version(), Some(minimum), "{profile:?}");
                assert_eq!(
                    config.max_proto_version(),
                    Some(SslVersion::TLS1_2),
                    "{profile:?}"
                );
                let error = config
                    .connect("fingerprint.test", Capture::default())
                    .unwrap_err();
                if minimum == SslVersion::TLS1_3 {
                    let boring::ssl::HandshakeError::Failure(stream) = error else {
                        panic!("a TLS1.3 minimum must not be lowered by the profile");
                    };
                    assert!(stream.get_ref().0.is_empty());
                } else {
                    let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
                        panic!("the TLS1.2 profile must emit its hello");
                    };
                    assert!(!stream.get_ref().0.is_empty());
                }
            }
        }
    }
}

#[test]
fn edge85_and_qq111_preserve_reference_versions_order_and_alps_difference() {
    for (profile, alps) in [
        (ClientFingerprint::Edge85, false),
        (ClientFingerprint::Qq111, true),
    ] {
        let (ciphers, extensions) = profile_fields(profile);
        assert!(grease(ciphers[0]));
        assert_eq!(&ciphers[1..4], [0x1301, 0x1302, 0x1303]);
        let ids: Vec<_> = extensions
            .iter()
            .map(|(kind, _)| *kind)
            .filter(|kind| !grease(*kind) && *kind != 21)
            .collect();
        let expected = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27];
        assert_eq!(&ids[..expected.len()], expected);
        assert_eq!(ids.contains(&17513), alps);
        assert!(!ids.contains(&17613));
        assert!(!ids.contains(&65037));
    }
}

#[test]
fn three_sixty75_keeps_tls12_groups_without_enabling_fake_or_disabled_algorithms() {
    let (ciphers, extensions) = profile_fields(ClientFingerprint::ThreeSixty75);
    assert_eq!(
        ciphers,
        [0xc00a, 0xc014, 0x0035, 0xc009, 0xc013, 0x002f, 0x000a]
    );
    let ids: Vec<_> = extensions.iter().map(|(kind, _)| *kind).collect();
    // Retain native EMS after the historical template's ordered extensions.
    assert_eq!(ids, [0, 65281, 10, 11, 35, 16, 5, 13, 23]);
    assert!(extensions
        .iter()
        .find(|(kind, _)| *kind == 23)
        .unwrap()
        .1
        .is_empty());
    let groups = &extensions.iter().find(|(kind, _)| *kind == 10).unwrap().1;
    assert_eq!(codes(&groups[2..]), [23, 24, 25]);
    assert!(!ids
        .iter()
        .any(|id| grease(*id) || matches!(id, 27 | 43 | 51 | 65037)));
    // No fake DHE/DSS, disabled AES256-SHA256, or RC4 becomes selectable.
    assert!(!ciphers
        .iter()
        .any(|id| matches!(id, 0x0039 | 0x006b | 0x003d | 0x0005 | 0xc007)));
}

#[test]
fn callers_without_alps_consumers_keep_h2_without_advertising_either_codepoint() {
    for profile in [
        ClientFingerprint::Chrome120,
        ClientFingerprint::Chrome155,
        ClientFingerprint::Qq111,
    ] {
        let (_, extensions) = profile_fields_with_settings(profile, false, SslVersion::TLS1_2);
        assert!(!extensions
            .iter()
            .any(|(kind, _)| matches!(kind, 17513 | 17613)));
        assert_eq!(
            extensions.iter().find(|(kind, _)| *kind == 16).unwrap().1,
            b"\0\x0c\x02h2\x08http/1.1"
        );
    }
}
