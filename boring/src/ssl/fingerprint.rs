//! Named, version-pinned ClientHello profiles. Authentication and IO are owned
//! by the caller; a profile never changes certificate verification or dials.
use super::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslConnectorBuilder, SslRef, SslVersion,
};
use crate::{cvt, error::ErrorStack, ffi};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};

/// Implemented ClientHello profiles, not aliases for the latest browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientFingerprint {
    /// Chrome 120's classic X25519 profile. Transport ALPN remains caller-owned.
    /// This does not emulate HTTP/2 settings, QUIC, actual ECH or browser runtime.
    Chrome120,
    /// iOS 14 stream profile, with CBC-SHA256 offers and no certificate compression.
    Ios14,
    /// Android 11 OkHttp's TLS 1.2 profile, without GREASE or compression.
    Android11,
    /// Edge 85, the current reference's default Edge profile.
    Edge85,
    /// 360 Browser 7.5's supported TLS 1.2 cipher and extension subset.
    ThreeSixty75,
    /// QQ 11.1, including its old-codepoint h2 ALPS declaration.
    Qq111,
    /// Chrome 155.0.8059.40 on macOS, with ML-DSA and advertised trust anchor IDs.
    Chrome155,
    /// Firefox 148 with a shared X25519 key across its hybrid and classic shares.
    Firefox148,
    /// Safari 26.3 with native X25519MLKEM768 and X25519 shares and Zlib.
    Safari263,
}

// A closed, bounded catalog, not user-supplied extension/cipher data. The native
// ID selects only encoding rules that existing BoringSSL APIs cannot express.
// Real key generation, negotiation, transcript and certificate proof stay native.
struct Profile {
    native_id: u32,
    ciphers: &'static str,
    groups: &'static [u16],
    key_shares: &'static [u16],
    signatures: &'static str,
    grease: bool,
    shuffle: bool,
    sct: bool,
    ech_grease: bool,
    alps_new_codepoint: Option<bool>,
    compression: &'static [Compression],
    requested_trust_anchors: &'static [u8],
    tls12_floor: bool,
    tls12_only: bool,
}

enum Compression {
    Brotli,
    Zlib,
    Zstd,
}

impl ClientFingerprint {
    fn profile(self) -> &'static Profile {
        match self {
            Self::Chrome120 => &CHROME120,
            Self::Ios14 => &IOS14,
            Self::Android11 => &ANDROID11,
            Self::Edge85 => &EDGE85,
            Self::ThreeSixty75 => &THREE_SIXTY75,
            Self::Qq111 => &QQ111,
            Self::Chrome155 => &CHROME155,
            Self::Firefox148 => &FIREFOX148,
            Self::Safari263 => &SAFARI263,
        }
    }
}

const CHROME120: Profile = Profile {
    native_id: 1,
    ciphers: concat!(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ),
    groups: &[29, 23, 24],
    key_shares: &[29],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
    ),
    grease: true,
    shuffle: true,
    sct: true,
    ech_grease: true,
    alps_new_codepoint: Some(false),
    compression: &[Compression::Brotli],
    requested_trust_anchors: &[],
    tls12_floor: false,
    tls12_only: false,
};

// Independently implemented from observed uTLS v1.8.8 HelloIOS_14 wire fields.
const IOS14: Profile = Profile {
    native_id: 5,
    ciphers: concat!(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
        "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:",
        "AES256-GCM-SHA384:AES128-GCM-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:",
        "ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
    ),
    groups: &[29, 23, 24, 25],
    key_shares: &[29],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:ecdsa_sha1:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1"
    ),
    grease: true,
    shuffle: false,
    sct: true,
    ech_grease: false,
    alps_new_codepoint: None,
    compression: &[],
    requested_trust_anchors: &[],
    tls12_floor: false,
    tls12_only: false,
};

// Fixed upstream profiles: MetaCubeX/utls HelloAndroid_11_OkHttp,
// HelloEdge_85, Hello360_7_5 and HelloQQ_11_1. Only implemented negotiation
// capabilities are enabled; fake DHE/DSA, RC4 and disabled CBC-SHA256 suites
// from the historical 360 hello are deliberately not made selectable.
const ANDROID11: Profile = Profile {
    native_id: 6,
    ciphers: concat!(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ),
    signatures: concat!(
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1"
    ),
    grease: false,
    shuffle: false,
    sct: false,
    ech_grease: false,
    alps_new_codepoint: None,
    compression: &[],
    tls12_only: true,
    ..CHROME120
};

const EDGE85: Profile = Profile {
    native_id: 7,
    shuffle: false,
    ech_grease: false,
    alps_new_codepoint: None,
    ..CHROME120
};

const THREE_SIXTY75: Profile = Profile {
    native_id: 8,
    ciphers: concat!(
        "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES256-SHA:",
        "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:DES-CBC3-SHA"
    ),
    groups: &[23, 24, 25],
    key_shares: &[],
    signatures: concat!(
        "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha1:",
        "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_sha1"
    ),
    ..ANDROID11
};

const QQ111: Profile = Profile {
    native_id: 9,
    alps_new_codepoint: Some(false),
    ..EDGE85
};

// The public IDs in the captured Chrome 155 trust_anchors extension. The
// native API takes the one-byte-length-prefixed IDs and encodes the list length.
// https://github.com/refraction-networking/utls/blob/360383f893fbe954ff12a701b87295406abbc156/testdata/chrome155_clienthello.hex
const CHROME155_TRUST_ANCHORS: &[u8] = b"\
    \x05\x82\xdf\x13\x02\x01\
    \x05\x82\xdf\x13\x02\x06\
    \x05\x82\xdf\x13\x02\x0d\
    \x05\x82\xdf\x13\x02\x0e\
    \x05\x82\xdf\x13\x02\x0f\
    \x05\x82\xdf\x13\x02\x12\
    \x05\x82\xdf\x13\x02\x13\
    \x05\x82\xdf\x13\x02\x14\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x07\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x08\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x09\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x0a\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x0b\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x0c\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x0d\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x12\
    \x08\x83\x9a\x64\x8c\x9b\x2d\x01\x13\
    \x04\xd6\x79\x09\x01\
    \x04\xd6\x79\x09\x04\
    \x04\xd6\x79\x09\x05\
    \x04\xd6\x79\x09\x06\
    \x04\xd6\x79\x09\x07\
    \x04\xd6\x79\x09\x08\
    \x04\xd6\x79\x09\x0a\
    \x04\xd6\x79\x09\x0b\
    \x04\xd6\x79\x09\x0c\
    \x04\xd6\x79\x09\x0d\
    \x04\xd6\x79\x09\x0f";

const CHROME155: Profile = Profile {
    native_id: 10,
    groups: &[4588, 29, 23, 24],
    key_shares: &[4588, 29],
    signatures: concat!(
        "mldsa44:mldsa65:mldsa87:",
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
    ),
    alps_new_codepoint: Some(true),
    requested_trust_anchors: CHROME155_TRUST_ANCHORS,
    tls12_floor: true,
    ..CHROME120
};

const FIREFOX148: Profile = Profile {
    native_id: 11,
    ciphers: concat!(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ),
    groups: &[4588, 29, 23, 24, 25],
    key_shares: &[4588, 29, 23],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:",
        "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:",
        "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1"
    ),
    grease: false,
    shuffle: false,
    sct: true,
    ech_grease: true,
    alps_new_codepoint: None,
    compression: &[Compression::Zlib, Compression::Brotli, Compression::Zstd],
    requested_trust_anchors: &[],
    tls12_floor: true,
    tls12_only: false,
};

const SAFARI263: Profile = Profile {
    native_id: 12,
    ciphers: concat!(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
        "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:",
        "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:",
        "ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
    ),
    groups: &[4588, 29, 23, 24, 25],
    key_shares: &[4588, 29],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1"
    ),
    grease: true,
    shuffle: false,
    sct: true,
    ech_grease: false,
    alps_new_codepoint: None,
    compression: &[Compression::Zlib],
    requested_trust_anchors: &[],
    tls12_floor: true,
    tls12_only: false,
};

/// Immutable profile plus caller-configured TLS trust, versions and identity.
/// Each connection supplies its transport ALPN; no profile can override it.
#[derive(Debug, Clone)]
pub struct FingerprintConnector {
    connector: SslConnector,
    profile: ClientFingerprint,
}

impl FingerprintConnector {
    /// Finishes a caller-owned builder with the selected handshake profile.
    /// Configure trust, TLS versions, client identity and session callbacks on
    /// `builder` first. This does not enable resumption or bypass verification.
    pub fn new(
        mut builder: SslConnectorBuilder,
        profile: ClientFingerprint,
    ) -> Result<Self, ErrorStack> {
        let spec = profile.profile();
        if spec.tls12_floor
            && builder
                .min_proto_version()
                .is_none_or(|minimum| minimum.0 < SslVersion::TLS1_2.0)
        {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        }
        if spec.tls12_only
            && builder
                .max_proto_version()
                .is_none_or(|maximum| maximum.0 > SslVersion::TLS1_2.0)
        {
            // Do not turn a historical TLS1.2 profile into a fake TLS1.3 hello.
            // Preserve a caller's stricter maximum and leave its minimum intact.
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        }
        builder.set_strict_cipher_list(spec.ciphers)?;
        builder.set_sigalgs_list(spec.signatures)?;
        builder.set_grease_enabled(spec.grease);
        builder.set_permute_extensions(spec.shuffle);
        if spec.sct {
            builder.enable_signed_cert_timestamps();
        }
        builder.enable_ocsp_stapling();
        for algorithm in spec.compression {
            match algorithm {
                Compression::Brotli => builder.add_certificate_compression_algorithm(Brotli)?,
                Compression::Zlib => builder.add_certificate_compression_algorithm(Zlib)?,
                Compression::Zstd => builder.add_certificate_compression_algorithm(Zstd)?,
            }
        }
        // These setters copy bounded static values; native code validates IDs.
        unsafe {
            cvt(ffi::SSL_CTX_set1_group_ids(
                builder.as_ptr(),
                spec.groups.as_ptr(),
                spec.groups.len(),
            ))?;
            ffi::SSL_CTX_set_max_cert_list(builder.as_ptr(), MAX_CERTIFICATE_BYTES);
        }
        Ok(Self {
            connector: builder.build(),
            profile,
        })
    }

    /// Prepares one connection. `alpn` uses TLS length-prefixed wire encoding;
    /// an empty slice sends no ALPN. The returned configuration still accepts
    /// per-connection SNI/verification and opt-in REALITY through their normal
    /// interfaces. Do not subsequently override its ALPN/profile settings.
    pub fn configure(&self, alpn: &[u8]) -> Result<ConnectConfiguration, ErrorStack> {
        self.configure_with_application_settings(alpn, true)
    }

    /// Prepares one connection, optionally declaring the profile's h2 ALPS.
    ///
    /// Set `application_settings` to false when the caller's HTTP/2 engine
    /// consumes standard SETTINGS frames but cannot import TLS ALPS. This only
    /// omits an optional extension; it never discards negotiated peer settings.
    /// The caller must not add ALPS later unless it can consume those settings.
    pub fn configure_with_application_settings(
        &self,
        alpn: &[u8],
        application_settings: bool,
    ) -> Result<ConnectConfiguration, ErrorStack> {
        let mut config = self.connector.configure()?;
        let spec = self.profile.profile();
        unsafe {
            cvt(ffi::SSL_set_client_fingerprint(
                config.as_ptr(),
                spec.native_id,
            ))?;
            cvt(ffi::SSL_set1_client_key_shares(
                config.as_ptr(),
                spec.key_shares.as_ptr(),
                spec.key_shares.len(),
            ))?;
            if !spec.requested_trust_anchors.is_empty() {
                cvt(ffi::SSL_set1_requested_trust_anchors(
                    config.as_ptr(),
                    spec.requested_trust_anchors.as_ptr(),
                    spec.requested_trust_anchors.len(),
                ))?;
            }
        }
        config.set_alpn_protos(alpn)?;
        config.set_enable_ech_grease(spec.ech_grease);
        let mut protocols = alpn;
        let mut offers_h2 = false;
        while let Some((&length, tail)) = protocols.split_first() {
            let Some((protocol, rest)) = tail.split_at_checked(usize::from(length)) else {
                // The public ALPN setter already rejects malformed input.
                return Err(ErrorStack::get());
            };
            offers_h2 |= protocol == b"h2";
            protocols = rest;
        }
        if let Some(new_codepoint) = spec
            .alps_new_codepoint
            .filter(|_| offers_h2 && application_settings)
        {
            unsafe {
                ffi::SSL_set_alps_use_new_codepoint(config.as_ptr(), new_codepoint.into());
                cvt(ffi::SSL_add_application_settings(
                    config.as_ptr(),
                    b"h2".as_ptr(),
                    2,
                    b"".as_ptr(),
                    0,
                ))?;
            }
        }
        Ok(config)
    }
}

impl SslRef {
    /// Returns the peer's negotiated ALPS bytes after a completed handshake.
    /// `None` is distinct from negotiated empty settings. TLS does not parse
    /// these application-owned bytes or configure an HTTP/2 implementation.
    /// The borrow cannot outlive or overlap mutation of this SSL connection.
    #[must_use]
    pub fn peer_application_settings(&self) -> Option<&[u8]> {
        // SAFETY: the native API returns SSL-owned storage. Its borrow is
        // bounded by &self. Avoid constructing a slice from a null empty buffer.
        unsafe {
            if ffi::SSL_has_application_settings(self.as_ptr()) != 1 {
                return None;
            }
            let mut data = std::ptr::null();
            let mut length = 0;
            ffi::SSL_get0_peer_application_settings(self.as_ptr(), &mut data, &mut length);
            Some(if length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(data, length)
            })
        }
    }
}

const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;

struct Zlib;
impl CertificateCompressor for Zlib {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        if input.len() > MAX_CERTIFICATE_BYTES {
            return Err(io::Error::other("compressed certificate limit"));
        }
        // Fixed bound, independent of the untrusted declared size. Require a
        // complete, checksummed stream and reject trailing concatenated data.
        let mut buffer = vec![0; MAX_CERTIFICATE_BYTES + 1];
        let mut decoder = flate2::Decompress::new(true);
        let status = decoder.decompress(input, &mut buffer, flate2::FlushDecompress::Finish)?;
        if status != flate2::Status::StreamEnd
            || decoder.total_in() != input.len() as u64
            || decoder.total_out() > MAX_CERTIFICATE_BYTES as u64
        {
            return Err(io::Error::other(
                "invalid or oversized certificate compression",
            ));
        }
        output.write_all(&buffer[..decoder.total_out() as usize])
    }
}

struct Brotli;
impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        if input.len() > MAX_CERTIFICATE_BYTES {
            return Err(io::Error::other("compressed certificate limit"));
        }
        let mut decoder = brotli::Decompressor::new(input, 4096);
        let mut buffer = [0; 4096];
        let mut total = 0;
        loop {
            let count = decoder.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            total += count;
            if total > MAX_CERTIFICATE_BYTES {
                return Err(io::Error::other("certificate output limit"));
            }
            output.write_all(&buffer[..count])?;
        }
    }
}

struct Zstd;
impl CertificateCompressor for Zstd {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        if input.len() > MAX_CERTIFICATE_BYTES {
            return Err(io::Error::other("compressed certificate limit"));
        }
        if !input.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            return Err(io::Error::other("invalid Zstandard certificate frame"));
        }
        // Using the slice directly preserves any input after the first frame.
        let mut decoder = zstd::stream::read::Decoder::with_buffer(input)?.single_frame();
        decoder.window_log_max(MAX_CERTIFICATE_BYTES.ilog2())?;
        io::copy(
            &mut decoder.by_ref().take(MAX_CERTIFICATE_BYTES as u64),
            output,
        )?;
        // At the output limit one more read completes the frame or detects overflow.
        if decoder.read(&mut [0])? != 0 || !decoder.into_inner().is_empty() {
            return Err(io::Error::other(
                "invalid or oversized certificate compression",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CertificateCompressor, Zstd, MAX_CERTIFICATE_BYTES};
    use std::io::{self, Write};

    #[test]
    fn zstd_decoder_accepts_a_single_checked_frame_at_the_certificate_limit() {
        let expected = vec![0xa5; MAX_CERTIFICATE_BYTES];
        let compressed = zstd::bulk::compress(&expected, 0).unwrap();
        let mut output = Vec::new();
        Zstd.decompress(&compressed, &mut output).unwrap();
        assert_eq!(output, expected);

        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.window_log(MAX_CERTIFICATE_BYTES.ilog2()).unwrap();
        encoder.write_all(b"certificate").unwrap();
        let mut checksummed = encoder.finish().unwrap();
        output.clear();
        Zstd.decompress(&checksummed, &mut output).unwrap();
        assert_eq!(output, b"certificate");
        *checksummed.last_mut().unwrap() ^= 1;
        assert!(Zstd.decompress(&checksummed, &mut io::sink()).is_err());
    }

    #[test]
    fn zstd_decoder_rejects_truncation_extra_frames_and_excessive_sizes() {
        let compressed = zstd::bulk::compress(b"certificate", 0).unwrap();
        let mut trailing = compressed.clone();
        trailing.push(0);
        let concatenated = [compressed.as_slice(), compressed.as_slice()].concat();
        // A full-size raw block produces exactly the allowed output. Its
        // framing makes the input exceed the limit.
        let mut over_input = b"\x28\xb5\x2f\xfd\x00\x38\x01\x00\x10".to_vec();
        over_input.resize(over_input.len() + MAX_CERTIFICATE_BYTES, 0);
        assert_eq!(
            zstd::bulk::decompress(&over_input, MAX_CERTIFICATE_BYTES)
                .unwrap()
                .len(),
            MAX_CERTIFICATE_BYTES
        );
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.window_log(MAX_CERTIFICATE_BYTES.ilog2()).unwrap();
        encoder
            .write_all(&vec![0; MAX_CERTIFICATE_BYTES + 1])
            .unwrap();
        let over_output = encoder.finish().unwrap();
        // A one-byte raw block framed with a 256 KiB decoder window.
        let over_window = b"\x28\xb5\x2f\xfd\x00\x40\x09\x00\x00a";
        assert_eq!(zstd::bulk::decompress(over_window, 1).unwrap(), b"a");
        for invalid in [
            &compressed[..compressed.len() - 1],
            &trailing,
            &concatenated,
            &over_input,
            &over_output,
            over_window,
            b"\x50\x2a\x4d\x18\x00\x00\x00\x00", // skippable frame
        ] {
            assert!(Zstd.decompress(invalid, &mut io::sink()).is_err());
        }
    }
}
