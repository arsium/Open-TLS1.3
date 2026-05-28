# TLSServer

A complete TLS 1.3 implementation in pure C# targeting .NET 9.0. Every cryptographic primitive runs through managed code — **no BCrypt / OpenSSL P/Invoke**. The published binary has a single bcrypt.dll import (`BCryptGenRandom`) which serves as the OS entropy source; everything else — hashes, HMACs, AEADs, EC point arithmetic, signatures — is pure C#. AES-NI is used via JIT-emitted CPU intrinsics (not a P/Invoke, gated by `Aes.IsSupported`), so the workhorse cipher stays hardware-fast while remaining portable to non-x86 CPUs.

![A TLS 1.3 session from this stack captured in Wireshark on the loopback interface: ClientHello (SNI=localhost), ServerHello, ChangeCipherSpec, and encrypted Application Data records, all recognised as TLSv1.3.](https://raw.githubusercontent.com/arsium/Open-TLS1.3/main/TLS1-3_1.png)

*A loopback session captured in Wireshark — the full TLS 1.3 handshake (ClientHello → ServerHello → ChangeCipherSpec → encrypted Application Data) is recognised as TLSv1.3 on the wire. The red `::1` RST rows at the top are the client's IPv6-first connection attempt against the v4-only demo listener (it then falls back to `127.0.0.1`); see the performance note below.*

> **Note 1 :** AI driven prompt project.

> **Note 2 :** a packable library project lives in `OpenTls13/` — `dotnet pack -c Release OpenTls13/OpenTls13.csproj` produces the `.nupkg` (multi-targets net8.0 / net9.0 / net10.0, AGPL-3.0-or-later, zero transitive dependencies). See *NuGet package* below.

> **Note 3 :** national-crypto suites (GOST, Chinese SM) are KAT-verified against published standard vectors and pass self-interop (this client ↔ this server), but have **not** yet been cross-validated against external stacks (GmSSL / OpenSSL-GOST). See *Limitations*.

## Features

### Protocol

- Full TLS 1.3 (RFC 8446) handshake — client and server, sync + async
- Mutual TLS (mTLS) with client certificate authentication
- PSK session resumption with NewSessionTicket
- 0-RTT early data
- Post-handshake key update (RFC 8446 §4.6.3) with usage-limit automation
- Post-handshake client authentication
- HelloRetryRequest with cookie support
- ALPN negotiation
- OCSP stapling (status_request)
- Encrypted Client Hello (ECH, RFC 9849) + HPKE (RFC 9180)
- GREASE (RFC 8701)
- record_size_limit negotiation (RFC 8449)
- Downgrade-protection sentinel check (RFC 8446 §4.1.3)
- Middlebox compatibility mode (ChangeCipherSpec)
- SSLKEYLOGFILE logging (Wireshark-compatible NSS Key Log Format)

### Cryptography

| Category | Algorithms |
|---|---|
| Key Exchange | X25519, X448, ECDH P-256, ECDH P-384, **X25519MLKEM768** (hybrid post-quantum), GOST curves (GC256A–D / GC512A–C), curveSM2 |
| Signatures | ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, Ed25519, RSA-PSS, RSA-PKCS#1 (legacy), GOST R 34.10-2012 (256/512), SM2 |
| AEAD Ciphers | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, Kuznyechik-MGM, Magma-MGM, SM4-GCM, SM4-CCM |
| Hash / KDF | SHA-256/384/512, HKDF (RFC 5869), Streebog-256/512, SM3, HMAC variants |
| Post-Quantum | ML-KEM-768 (FIPS 203) with NTT-based polynomial arithmetic |
| Keccak Sponge | SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 (pure managed) |
| National | GOST R 34.11/34.12/34.13-2015 (RFC 9367), Chinese SM2/SM3/SM4 (RFC 8998) |
| Certificates | X.509 v3 generation (incl. GOST / SM2 certs), CA chaining, PKCS#12/PFX, PKCS#7 |
| Compression | Certificate compression (RFC 8879) via Brotli and Zstandard |

Symmetric primitives (AES-GCM, SHA-2 family, HMAC) and the asymmetric handshake primitives (RSA, NIST P-256/P-384/P-521 ECDSA/ECDH, X25519, X448) go through BouncyCastle's vendored pure-managed implementations — no `System.Security.Cryptography.*` runtime calls into BCrypt or OpenSSL. The NIST EC paths use BouncyCastle's optimized `Custom*Curve` classes (`CustomNamedCurves`) and X25519/X448 use its `Rfc7748` packed-limb implementations — both far lighter on allocations than a generic `System.Numerics.BigInteger` ladder. ChaCha20-Poly1305 is a hand-written RFC 8439 implementation. The ML-KEM-768 NTT/InvNTT, Ed25519, SM2/SM3/SM4, and Keccak are implemented from scratch. GOST primitives are vendored from OpenGost, with EC scalar-mult on Jacobian projective coordinates (one modular inverse per scalar mult instead of one per point operation).

### Cipher suites

| Suite | Spec |
|---|---|
| TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 | RFC 8446 |
| TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L / _S | RFC 9367 |
| TLS_GOSTR341112_256_WITH_MAGMA_MGM_L / _S | RFC 9367 |
| TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3 | RFC 8998 |

### Vendored sources (MIT / BSD / Apache 2.0)

- [BouncyCastle (bc-csharp)](https://github.com/bcgit/bc-csharp) — AES + GCM mode, SHA-2 digests, HMAC, RSA, NIST EC curves, BigInteger, ASN.1 (`TLS/BouncyCastle/`, ~1330 files)
- [BrotliSharpLib](https://github.com/master131/BrotliSharpLib) — Brotli for RFC 8879 cert compression, replaces `System.IO.Compression.BrotliStream` (`TLS/BrotliSharp/`, 58 files)
- [ZstdSharp](https://github.com/oleg-st/ZstdSharp) — Zstandard for RFC 8879 cert compression (`TLS/Zstd/`)
- [OpenGost](https://github.com/sergezhigunov/OpenGost) — GOST Kuznyechik / Magma block ciphers, Streebog hash, GOST R 34.10-2012 (`TLS/OpenGost/`, ~18 files; the upstream `HashAlgorithm` / `SymmetricAlgorithm` / `ECDsa` base-class inheritance has been stripped so the BCL crypto registry — and its BCrypt imports — don't get linked)

### Architecture

```
Open-TLS1.3.sln
├── TLS/                    # Shared project — core TLS library
│   ├── TlsConnection.cs    # Handshake state machine (sync + async)
│   ├── RecordLayer.cs      # Record framing, AEAD encryption, fragmentation
│   ├── KeySchedule.cs      # TLS 1.3 key schedule (RFC 8446 §7)
│   ├── Hkdf.cs             # HKDF + HKDF-Expand-Label (multi-hash)
│   ├── AeadCipher.cs       # AES-GCM / ChaCha20 / MGM / SM4-GCM/CCM dispatch
│   ├── AesGcmManaged.cs    # AES-GCM via BC AesEngine + GcmBlockCipher (cached per instance)
│   ├── ChaCha20.cs / Poly1305.cs / ChaCha20Poly1305Managed.cs  # RFC 8439 from scratch
│   ├── Sha2Managed.cs      # SHA-2 / HMAC-SHA wrappers over BC digests (IncrementalSha2 for transcript)
│   ├── RsaManaged.cs / EcdsaManaged.cs  # BC RSA / NIST EC wrappers
│   ├── Ed25519.cs / X25519.cs / X448.cs / EcdhP256.cs / EcdhP384.cs
│   ├── MlKem768.cs         # FIPS 203 ML-KEM-768
│   ├── Keccak.cs           # Keccak-f[1600] sponge (SHA3/SHAKE)
│   ├── Hpke.cs             # HPKE (RFC 9180)
│   ├── EncryptedClientHello.cs  # ECH (RFC 9849)
│   ├── Mgm.cs              # GOST MGM AEAD (RFC 9058/9367), packed-ulong GF(2^128)
│   ├── GostCrypto.cs / GostKdf.cs / GostEcdh.cs  # GOST facade, Streebog KDF, GOST ECDH
│   ├── OpenGost/           # Vendored GOST + Jacobian EC scalar-mult
│   ├── ChineseCrypto.cs    # SM2 / SM3 / SM4 (SM2 EC math = Jacobian projective)
│   ├── Sm4Aead.cs / Sm3Kdf.cs   # SM4-GCM/CCM AEAD, SM3 KDF
│   ├── Grease.cs           # GREASE (RFC 8701)
│   ├── CertificateUtils.cs # X.509 generation (incl. GOST/SM2), CA chaining
│   ├── Asn1.cs / Pkcs12.cs / Pkcs7.cs   # DER, PFX, PKCS#7
│   ├── SessionTicket.cs / KeyLogger.cs / CertificateCompression.cs
│   ├── BouncyCastle/       # Vendored BC core (crypto, math, security, util, asn1)
│   ├── BrotliSharp/        # Vendored Brotli for RFC 8879
│   └── Zstd/               # Vendored Zstandard for RFC 8879
├── TLSServer/  TLSClient/  TLSServerAsync/  TLSClientAsync/   # demo apps
└── Tests/                  # Test-vector + loopback suite (dependency-free)
```

## Quick Start

### Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)

### Build

```bash
dotnet build Open-TLS1.3.sln
```

### Run

Start the server (listens on port 8443 with mTLS):

```bash
dotnet run --project TLSServer
```

Connect with the client:

```bash
dotnet run --project TLSClient
```

For async variants:

```bash
dotnet run --project TLSServerAsync
# In another terminal:
dotnet run --project TLSClientAsync
```

The server auto-generates a CA and server certificate at startup and exports `client.pfx` for mTLS client authentication.

### Selecting national cipher suites (client)

```csharp
var client = new TlsClient
{
    CipherSuites = new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L },
    NamedGroups  = new[] { NamedGroup.GC256A }   // GOST-curve key exchange
};
// server side: var cert = CertificateUtils.IssueGostCertificate("host", ca, CertificateProfile.Server, SignatureScheme.Gostr34102012_256a);
//              or            CertificateUtils.IssueSm2Certificate("host", ca, CertificateProfile.Server);
```

### Wireshark Decryption

Set the `SSLKEYLOGFILE` environment variable before running the server or client to enable key logging:

```bash
export SSLKEYLOGFILE=~/keys.log
dotnet run --project TLSServer
```

Then point Wireshark to the key log file under *Preferences > Protocols > TLS > (Pre)-Master-Secret log filename*.

## Tests

A dependency-free test suite lives in `Tests/` (known-answer vectors + end-to-end loopback matrix).

```bash
dotnet run -c Release --project Tests           # all tests (83 KAT + loopback + record-layer + wire-format round-trips)
dotnet run -c Release --project Tests bench     # AEAD throughput + handshake + bulk-transfer benchmarks
dotnet run -c Release --project Tests profile   # per-phase allocation breakdown of one handshake per suite
dotnet run -c Release --project Tests bulk      # 20 MB + 50 MB bulk loopback (AES-128/256-GCM + ChaCha20)
dotnet run -c Release --project Tests fuzz      # parser fuzz harness (120k inputs across 12 parsers)
dotnet run -c Release --project Tests fuzz 50000  # heavier fuzz (~600k inputs)
```

Coverage includes KATs vs published vectors (MGM RFC 9058, SM4/SM3 GB/T, SM4-GCM/CCM RFC 8998, Streebog, GOST R 34.10-2012 and SM2 signatures, HKDF RFC 5869, X25519 RFC 7748, ChaCha20 / Poly1305 / AEAD-ChaCha20-Poly1305 RFC 8439) and full handshake+data loopbacks for every cipher suite plus mTLS plus RFC 8879 cert compression.

### Measured performance (loopback, single-thread, this dev box)

Bulk data throughput (50 MB, end-to-end through TLS record framing):

| Cipher | Throughput |
|---|---|
| AES-128-GCM | ~90–100 MB/s |
| AES-256-GCM | ~90–100 MB/s |
| ChaCha20-Poly1305 (managed RFC 8439) | ~85–95 MB/s |

Full TLS 1.3 handshake (loopback, after the allocation overhaul — see `changelog.txt`):

| Suite | Latency | Allocation / handshake |
|---|---|---|
| default (X25519 + AES-256-GCM + ECDSA P-256 cert) | ~5–7 ms | ~1.05 MB |
| GOST (Kuznyechik-MGM + GC256A + GOST cert) | ~14 ms | ~6.4 MB |
| SM (SM4-GCM + curveSM2 + SM2 cert) | ~13 ms | ~7.3 MB |

> Earlier revisions of this table reported ~2 s GOST/SM handshakes — that was an
> IPv6 loopback-fallback artifact in the benchmark (the client resolved `localhost`
> to `::1` first, where the v4-only listener refused it, then fell back to v4 after
> ~2 s of SYN→RST backoff). The benchmark now connects to `127.0.0.1` directly.
> National-suite latency is dominated by their `System.Numerics.BigInteger`-based EC
> scalar multiplication; the default suite uses BouncyCastle's optimized curve paths.
> Bulk throughput is cipher-bound, not allocation-bound, so it is unchanged by the
> allocation work — that work cut per-handshake allocation ~10× and per-record bulk
> allocation ~14× (see `changelog.txt` for the before/after numbers).

## Native AOT

All projects are configured for native AOT compilation:

```bash
dotnet publish -c Release --project TLSServer
```

## NuGet package

The core library ships as a packable class library in `OpenTls13/` that compiles the
shared `TLS/` sources (plus the vendored BouncyCastle / BrotliSharpLib / ZstdSharp /
OpenGost) into a single `OpenTls13.dll` — **zero transitive NuGet dependencies**.

```bash
dotnet pack -c Release OpenTls13/OpenTls13.csproj
# → OpenTls13/bin/Release/OpenTls13.<version>.nupkg  (+ .snupkg symbols)
```

- **Package id:** `OpenTls13`  ·  **License:** `AGPL-3.0-or-later`  ·  **Targets:** net8.0 / net9.0 / net10.0
- AOT-friendly (the demo apps publish with `PublishAot=true`), though `IsAotCompatible`
  is intentionally left off the library to avoid analyzer noise from the vendored crypto.
- Consume it with only the public API (`TlsServer`, `TlsClient`, `TlsStream`,
  `CertificateUtils`, `CipherSuite`, `NamedGroup`, …):

```csharp
using TLS;
var ca   = CertificateUtils.GenerateCA("My CA");
var cert = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);
var server = new TlsServer(cert);
server.Listen(8443);
using var s = server.Accept();          // TlsStream — Read/Write encrypted app data
```

> **AGPL note:** AGPL-3.0 is strong copyleft — network use of a derivative obliges source
> disclosure. The vendored crypto stays under its original permissive MIT / Bouncy Castle
> terms (see `OpenTls13/THIRD-PARTY-NOTICES.txt`); only the OpenTls13 code as a whole is AGPL.
> If you need a non-copyleft option, dual-licensing is the author's call.

## RFC Compliance

Core TLS 1.3 (RFC 8446) is compliant — handshake, HelloRetryRequest + cookie, middlebox-compat, 0-RTT, KeyUpdate, post-handshake auth, alerts, and downgrade-sentinel checking.

| Specification | Coverage |
|---|---|
| RFC 8446 | TLS 1.3 protocol, handshake, record layer, key schedule |
| RFC 8701 | GREASE |
| RFC 8449 | record_size_limit |
| RFC 7748 | X25519 and X448 Diffie-Hellman |
| RFC 8032 | Ed25519 signatures |
| RFC 5869 | HKDF key derivation |
| RFC 8879 | Certificate compression (Brotli, Zstandard) |
| RFC 8937 | Randomness wrapper |
| RFC 9149 | Ticket request extension |
| RFC 9258 | External PSK importer |
| RFC 9261 | Exported authenticators |
| RFC 9266 | TLS channel binding |
| RFC 9963 | Legacy RSA PKCS#1 signature schemes (cert verification) |
| RFC 9180 | HPKE (Hybrid Public Key Encryption) |
| RFC 9849 | Encrypted Client Hello (ECH) |
| RFC 9367 / 9058 | GOST cipher suites (Kuznyechik/Magma MGM, Streebog, GOST R 34.10-2012, GOST curves) |
| RFC 8998 | Chinese SM cipher suites (SM4-GCM/CCM, SM3, SM2, curveSM2) |
| FIPS 203 | ML-KEM-768 (Module-Lattice Key Encapsulation) |
| draft-ietf-tls-ecdhe-mlkem | X25519MLKEM768 hybrid key exchange |

## Limitations

- **External interop is unverified.** This stack passes its own loopback matrix end-to-end (and 120 k+ fuzz inputs across all message parsers without unhandled exceptions), but has not been cross-tested against OpenSSL, BoringSSL, nginx, curl, GmSSL, or OpenSSL-GOST. Production use should validate against the target peer first. In particular, this stack emits Streebog digests in the reverse byte order of RFC 6986's textual presentation, and the GOST/SM CertificateVerify hashing is internally self-consistent — byte-order conventions should be validated before relying on external national-suite interop.
- **National AEAD throughput is bound by the managed implementation.** Hardware-accelerated AES-GCM does ~100 MB/s end-to-end through TLS framing; managed Kuznyechik / Magma / SM4 are an order of magnitude slower (tens of MB/s) and dominated by their per-block cost. GOST and SM2 scalar-mult is on Jacobian coordinates (one modular inverse per scalar mult, ~18% faster than the previous affine implementation).
- The on-wire ClientHello `signature_algorithms` / `supported_groups` advertise the standard set only; national schemes/curves work in self-interop because the server selects directly.
- `max_fragment_length` (RFC 6066) is intentionally not sent (superseded by `record_size_limit`).
- TLS 1.2 fallback is out of scope by design — this is a TLS-1.3-only stack.
