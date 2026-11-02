# Named ClientHello profiles

The fork follows boring 5.4.0 and the official BoringSSL 0.20261020.0 baseline
(`d3bf4795ad5b79d646cddf2fec687da5b9b502db`). Native extensions remain opt-in
build patches; the checked-out BoringSSL submodule contains upstream source.

Enable `boring/client-fingerprint` or `tokio-boring/client-fingerprint` on this
fork. The implemented fixed profiles are `ClientFingerprint::Chrome120` (classic
X25519), `Chrome133` (ordinary TLS with native X25519MLKEM768 and X25519 shares,
new ALPS and no padding), `Firefox120` (X25519/P-256 shares and fixed order) and
`Safari16` (Safari 16.0, fixed order and Zlib) and `Ios14` (iOS 14, fixed order,
CBC-SHA256 offers and no certificate compression), `Android11` (Android 11
OkHttp), `Edge85`, `ThreeSixty75` (360 Browser 7.5) and `Qq111` (QQ 11.1).
Android11 and ThreeSixty75 cap negotiation at TLS 1.2; a caller's higher minimum
is still enforced rather than lowered. They are not aliases following a
browser release automatically. Unknown profile names
must be rejected by applications; this library does not silently map them to a
different browser.

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
extension permutation, SCT/OCSP, ECH GREASE and template-specific h2 ALPS. Certificate
compression uses real Brotli for Chrome and Zlib for Safari; Firefox and iOS do not
advertise it. This is not an advertised-only extension. The
native certificate-message allocation and decoder output are bounded to 128 KiB.
The profile does not disable certificate verification, weaken handshake signature
verification, enable early data or create a resumption policy.

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

## REALITY

With both features enabled, use the same connector and set
`RealityClientConfig` on its fresh connection before the handshake. The profile
does not add Ed25519 to the Chrome120 signature list. The authenticated REALITY
exception and native CertificateVerify checks remain in the native handshake.
The full connection-local invariants and deliberately unsupported combinations
are documented in [REALITY](reality-client.md).

The [CF4 fork-local checks](client-fingerprint-cf4-fork.md) cover the four originally accepted
profiles' classic REALITY shape and authentication binding. Classic mode removes
Chrome133's ML-KEM group/share and preserves Firefox's additional P-256 share.
Independent VCore/Mihomo data paths still require application integration and
fresh container acceptance; ordinary-TLS ML-KEM is not PQ REALITY.

For explicit hybrid REALITY, only Chrome133 among this fixed catalog has the
required group/share. Configure `RealityClientConfig::require_x25519mlkem768`
separately; classic remains the default. The other fixed profiles fail rather
than changing their wire identities. Both actual hybrid negotiation and native
REALITY authentication are required. See the independent [hybrid fork gate](reality-hybrid.md);
its checks do not establish VCore's production/download-leg support.

`RealityClientConfig::allow_x25519mlkem768` instead preserves the profile's actual
shares and allows either classic or hybrid selection within the same authenticated
handshake. A classic profile remains classic; this does not invent a hybrid share
or retry a rejected connection. Classic mode remains the default, and required
hybrid mode keeps its existing requirement.

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

Applications must set their TLS version floor (VCore uses TLS1.2), which trims
Safari's reference TLS1.0/1.1 advertisement. Safari omits the cold session-ticket
extension. Actual caller-supplied TLS1.2 tickets can still use it; warm connections
are not claimed as identical to the reference cold template. Zlib rejects
truncation, corrupt checksums, trailing bytes and oversized output before passing
the certificate to the unchanged verifier.

TLS1.3 cipher order and Chrome ECH GREASE AEAD are fixed by the named template,
not CPU AES acceleration. Real native cipher filtering, key generation,
transcript and proof-of-key remain intact. No BIO rewriting or global state is
introduced; the unconfigured native path is unchanged.

Targeted checks create only memory streams, including real native TLS peers:

```sh
cargo test -p boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint --test reality --test hkdf
cargo test -p tokio-boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo clippy -p boring -p tokio-boring --features reality,client-fingerprint --lib -- -D warnings
cargo fmt --all -- --check
```

The earlier isolated Mihomo, ordinary-TLS, Vision and handshake experiments are
selection/integration evidence, not reasons to repeat general backend feasibility
work. The tests above exercise the new named interface. Application wiring,
portable pinned Git dependency resolution, device behavior and release review are
separate gates; passing these library tests does not complete those gates.

### Historical initial-interface result — 2026-09-25

On macOS ARM64, the current named interface passed one wire-profile test, eight
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
