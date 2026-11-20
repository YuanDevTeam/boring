# Named ClientHello profiles

The fork follows boring 5.5.1 and the official BoringSSL 0.20261020.0 baseline
(`d3bf4795ad5b79d646cddf2fec687da5b9b502db`). Native extensions remain opt-in
build patches; the checked-out BoringSSL submodule contains upstream source.

Enable `boring/client-fingerprint` or `tokio-boring/client-fingerprint` on this
fork. Each `ClientFingerprint` variant selects a fixed profile.

| Family | Variants |
| --- | --- |
| Chrome | `Chrome120`, `Chrome133`, `Chrome155` |
| Firefox | `Firefox120`, `Firefox148` |
| Safari | `Safari16` (16.0), `Safari263` (26.3) |
| iOS and Android | `Ios14`, `Android11` (OkHttp) |
| Edge, 360 Browser and QQ | `Edge85`, `ThreeSixty75` (7.5), `Qq111` (11.1) |

Existing variants retain their version and encoding. Applications must reject
unknown names and explicitly select any newer variant. `Android11` and
`ThreeSixty75` cap negotiation at TLS 1.2 and retain any stricter caller floor.
`Chrome120` offers a classic X25519 share. `Chrome133` adds a hybrid share and
the newer optional ALPS codepoint, and omits padding. `Firefox120` offers X25519
and P-256 shares in a fixed order.

## Interface

`FingerprintConnector` finishes a caller-configured `SslConnectorBuilder` with
the selected profile. It owns no sockets, DNS, tasks or session cache. Trust,
client identity, permitted TLS versions and session callbacks stay with the
caller. Each `configure` call creates a fresh connection with transport-owned
ALPN:

```rust
use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector, SslMethod};

let builder = SslConnector::builder(SslMethod::tls())?;
// Set custom trust, client identity, version restrictions or bounded session
// callbacks on the builder here, if the application needs them.
let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome120)?;
let configuration = connector.configure(b"\x02h2\x08http/1.1")?;
// Pass configuration and an already connected stream to tokio_boring::connect,
// or use configuration.connect for blocking IO. No additional dial occurs.
# Ok::<(), boring::error::ErrorStack>(())
```

ALPN uses the existing TLS length-prefixed format. An empty list sends neither
ALPN nor ALPS; offering HTTP/1.1 alone does not advertise h2 ALPS. Callers must not
change the returned configuration's ALPN or profile fields afterwards. SNI,
verification and opt-in REALITY use their normal connection-level interfaces.
Restricting TLS versions or ALPN intentionally changes the resulting wire shape.

`configure_with_application_settings(alpn, false)` omits the profile's optional
h2 ALPS declaration when the caller's HTTP/2 engine cannot consume negotiated
application settings. It retains the requested ALPN, including h2, and does not
discard already-negotiated settings. `configure(alpn)` remains equivalent to
`configure_with_application_settings(alpn, true)`, preserving existing behavior.

The profile configures ciphers, supported groups, signature algorithms, GREASE,
extension permutation, SCT/OCSP, ECH GREASE and template-specific h2 ALPS.
Chrome uses Brotli certificate decompression and Safari uses Zlib.
`Firefox148` offers actual Zlib, Brotli and Zstd decoders in that order.
`Firefox120` and `Ios14` omit certificate compression. The native certificate
message allocation and decoder output are bounded to 128 KiB. The Zstd decoder
also limits its window to 128 KiB and requires a single complete frame.
Certificate and handshake signature verification stay active. The caller still
controls early data and owns session storage.

Edge85 and Qq111 preserve their fixed reference ordering; QQ declares old-codepoint
h2 ALPS when enabled, while Edge does not. Android11 and ThreeSixty75 do not add
GREASE or certificate compression. ThreeSixty75 exposes the implemented TLS 1.2
subset; historical fake DHE/DSA, RC4 and disabled CBC-SHA256 suites are not made
selectable.
ThreeSixty75 also retains native TLS 1.2 Extended Master Secret (EMS, extension
23), appended after the template's ordered extensions. The historical
`Hello360_7_5` template omits EMS. This deliberate deviation preserves native EMS
negotiation. The profile does not add the template's NPN or fake Channel ID
declarations; ThreeSixty75 is a supported subset rather than an exact historical
wire identity.

`SslRef::peer_application_settings()` returns borrowed negotiated ALPS data:
`None` means absent, `Some(&[])` means negotiated with empty peer settings. TLS
only transports these bytes; the application remains responsible for interpreting
them and enforcing its required ALPN before using or caching the connection.

## Recent profiles

- `Chrome155` offers native X25519MLKEM768 and X25519 shares, GREASE followed
  by native TLS 1.3 ML-DSA-44/65/87 signature schemes, and the newer h2 ALPS
  codepoint when ALPS is enabled. The per-connection `trust_anchors` extension
  requests the 28 identifiers recorded in the Chrome 155 reference. The IDs
  can influence the peer's certificate chain choice. The caller's trust store
  and certificate verifier still determine acceptance. The profile does not
  initiate an anchor-discovery retry.
  [Chrome 155 reference](https://github.com/refraction-networking/utls/blob/360383f893fbe954ff12a701b87295406abbc156/testdata/chrome155_clienthello.md)
- `Firefox148` generates X25519MLKEM768, X25519 and P-256 shares in that order.
  The hybrid and standalone X25519 entries use one ephemeral X25519 key within
  each ClientHello. A cold connection omits the TLS 1.2 ticket extension and
  TLS 1.3 PSK modes. The native handshake can send a real TLS 1.2 ticket or
  TLS 1.3 PSK and its required modes when an eligible session is available.
  A cold peer may decline to issue a TLS 1.3 ticket.
- `Safari263` offers independently generated X25519MLKEM768 and X25519 shares,
  uses a fixed extension order and TLS 1.3 cipher order, and omits padding.
  `Chrome155`, `Firefox148`, and `Safari263` require at least TLS 1.2 and
  retain a stricter caller floor.

## REALITY

With both features enabled, use the same connector and set
`RealityClientConfig` on its fresh connection before the handshake. The profile
does not add Ed25519 to the Chrome120 signature list. The authenticated REALITY
exception and native CertificateVerify checks remain in the native handshake.
The full connection-local invariants and deliberately unsupported combinations
are documented in [REALITY](reality-client.md).

Classic mode remains the default. It removes X25519MLKEM768 from both the
advertised groups and the actual key shares of hybrid-capable profiles while
preserving the remaining shares, including Firefox's P-256.
The [CF4 fork-local checks](client-fingerprint-cf4-fork.md) preserve the original
profile coverage.

`Chrome133`, `Chrome155`, `Firefox148` and `Safari263` offer the native group
and share needed by `RealityClientConfig::require_x25519mlkem768`. This mode
requires actual hybrid negotiation and native REALITY authentication. The other
fixed profiles fail when hybrid is required. `allow_x25519mlkem768` preserves
the selected profile's existing shares and accepts either supported choice
within the same authenticated handshake. Rejected handshakes terminate without
a retry. REALITY identity remains bound to X25519 and its native verification.
See the [hybrid fork gate](reality-hybrid.md) for the original independent checks.

## Scope and verification

This is TLS ClientHello shaping, not HTTP/2/browser runtime impersonation, actual
ECH, QUIC/H3 shaping, or a claim that all Mihomo client-fingerprint names work.
Default builds do not enable either new feature.

The feature now forwards to `boring-sys/client-fingerprint`, which applies a
small bundled-source patch. It exposes only an implemented native profile ID,
never arbitrary extension bytes. Stream-client configuration is checked before
IO; DTLS, QUIC, already-started or repeated native selection fails. FIPS, RPK and
external/precompiled BoringSSL are rejected at build time. Profiles share one
bounded internal catalog for cipher/signature lists, ordered groups and separate
key shares, permutation, ECH, ALPS codepoint and compression.

Firefox's FFDHE groups, delegated-credential and record-size-limit declarations
are template-only, as in the source uTLS template, not new RFC implementations.
Selection of an unavailable group or a ServerHello response to these extensions
fails closed. Safari's 0xc008 cipher is likewise template-only in uTLS and is
rejected if selected. Its real 0xc012 ECDHE-RSA-3DES suite reuses native primitives
and is deprecated/default-off outside explicit cipher configuration. No RC4 was
restored. Safari's repeated signature scheme is a wire encoding detail; real
signature verification preferences remain unique.

For `Safari16`, a caller's TLS 1.2 floor trims the reference TLS 1.0/1.1
advertisement. Both Safari profiles omit the cold session-ticket extension. An
eligible TLS 1.2 ticket can still be offered on a warm connection. Zlib rejects
truncation, corrupt checksums, trailing bytes and oversized output before passing
the certificate to the verifier.

TLS1.3 cipher order and Chrome ECH GREASE AEAD are fixed by the named template,
not CPU AES acceleration. Real native cipher filtering, key generation,
transcript and proof-of-key remain intact. No BIO rewriting or global state is
introduced; the unconfigured native path is unchanged.

Targeted checks create only memory streams, including real native TLS peers:

```sh
cargo test -p boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint --test reality --test hkdf
cargo test -p boring --features client-fingerprint --lib zstd_decoder_
cargo test -p tokio-boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo clippy -p boring -p tokio-boring --features reality,client-fingerprint --lib -- -D warnings
cargo fmt --all -- --check
```

These checks cover the library's wire encoding, certificate decompression and
native handshakes. Application wiring, locked Git dependency resolution,
interoperability with external peers, device behavior and release review require
separate validation.

### Historical initial-interface result — 2026-09-25

On macOS ARM64, the initial named interface passed one wire-profile test, eight
REALITY tests (including the named-profile authentication case), nine existing
HKDF tests and two Tokio memory-handshake tests: 20 total. The Tokio tests cover
absent/empty/nonempty peer ALPS and actual Brotli certificate decoding with both
accepting and rejecting caller verification callbacks. The wire-profile test also
passed with `client-fingerprint` alone, without compiling REALITY. Focused library
and profile-test Clippy with `-D warnings`, formatting and diff checks passed.

These checks did not create a network listener. No new container interoperability,
cross-target or device result is claimed for this interface change. At the time
of this validation the fork branch was local/unpublished; the initial VCore
dependency-resolution attempt was removed rather than leaving a sibling path
dependency or an unresolved lockfile. Publishing this branch makes its interfaces
available for a pinned Git dependency; VCore integration is validated separately.

## iOS 14 source and cipher boundary

`Ios14` is independently implemented from the wire fields in the official
[uTLS v1.8.8 iOS14 template](https://github.com/MetaCubeX/utls/blob/v1.8.8/u_parrots.go#L1654).
The native catalog has its own profile ID and cipher list. It offers the real
CBC-SHA256 suites c023, c027 and 003c; the last uses existing native RSA,
AES-128-CBC, HMAC-SHA256 and TLS1.2 PRF primitives. It remains deprecated and
excluded from default cipher aliases. No TLS1.0/1.1 floor is restored by the profile.

The reference's disabled c024, c028 and 003d, and its template-only c008, are
wire declarations whose actual selection fails. Certificate compression is
absent. Signature duplication, cold ticket omission, GREASE and conditional
padding are connection-local encoding rules. Trust, identity, ALPN, TLS versions,
transcript, key generation and Finished remain native and caller-owned.
The uTLS source was used only as a behavior reference; no Go functions were
copied or translated. Existing BoringSSL and Rust wrapper licenses are retained.
