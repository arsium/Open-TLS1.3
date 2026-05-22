# TLSServer

A complete TLS 1.3 implementation in pure C# targeting .NET 9.0. Every protocol layer — from the record framing and handshake state machine down to the elliptic-curve arithmetic and post-quantum key exchange — is written from scratch with zero external dependencies (except .NET's built-in AES-GCM and ChaCha20-Poly1305 AEAD primitives).

> **Note 1 :** AI driven prompt project.

> **Note 2 :** if you wanna a nuget package including DLLs, create a pull request

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

All elliptic-curve operations (point addition, doubling, scalar multiplication) and the ML-KEM NTT/InvNTT are implemented from scratch using `System.Numerics.BigInteger` — no platform-specific or third-party crypto libraries. The GOST primitives are vendored from the OpenGost project; SM2/SM3/SM4 are implemented from the GB/T standards.

### Cipher suites

| Suite | Spec |
|---|---|
| TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 | RFC 8446 |
| TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L / _S | RFC 9367 |
| TLS_GOSTR341112_256_WITH_MAGMA_MGM_L / _S | RFC 9367 |
| TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3 | RFC 8998 |

### Sources & lib directly imported from files

- [OpenGost](https://github.com/sergezhigunov/OpenGost)
- [ZstdSharp](https://github.com/oleg-st/ZstdSharp)
- [BouncyCastle](https://github.com/bcgit/bc-csharp)

### Architecture

```
Open-TLS1.3.sln
├── TLS/                    # Shared project — core TLS library
│   ├── TlsConnection.cs    # Handshake state machine (sync + async)
│   ├── RecordLayer.cs      # Record framing, AEAD encryption, fragmentation
│   ├── KeySchedule.cs      # TLS 1.3 key schedule (RFC 8446 §7)
│   ├── Hkdf.cs             # HKDF + HKDF-Expand-Label (multi-hash)
│   ├── AeadCipher.cs       # AES-GCM / ChaCha20 / MGM / SM4-GCM/CCM dispatch
│   ├── Ed25519.cs / X25519.cs / X448.cs / EcdhP256.cs / EcdhP384.cs
│   ├── MlKem768.cs         # FIPS 203 ML-KEM-768
│   ├── Keccak.cs           # Keccak-f[1600] sponge (SHA3/SHAKE)
│   ├── Hpke.cs             # HPKE (RFC 9180)
│   ├── EncryptedClientHello.cs  # ECH (RFC 9849)
│   ├── Mgm.cs              # GOST MGM AEAD (RFC 9058/9367)
│   ├── GostCrypto.cs / GostKdf.cs / GostEcdh.cs  # GOST facade, Streebog KDF, GOST ECDH
│   ├── OpenGost/           # Vendored GOST: Kuznyechik, Magma, Streebog, GostECDsa, curves
│   ├── ChineseCrypto.cs    # SM2 / SM3 / SM4
│   ├── Sm4Aead.cs / Sm3Kdf.cs   # SM4-GCM/CCM AEAD, SM3 KDF
│   ├── Grease.cs           # GREASE (RFC 8701)
│   ├── CertificateUtils.cs # X.509 generation (incl. GOST/SM2), CA chaining
│   ├── Asn1.cs / Pkcs12.cs / Pkcs7.cs   # DER, PFX, PKCS#7
│   ├── SessionTicket.cs / KeyLogger.cs / CertificateCompression.cs
│   └── Zstd/               # Pure managed Zstandard implementation
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
dotnet run -c Release --project Tests          # run all tests (exit code 0 = pass)
dotnet run -c Release --project Tests bench     # throughput + handshake benchmarks
```

Coverage includes KATs vs published vectors (MGM/RFC 9058, SM4/SM3 GB/T, SM4-GCM/CCM RFC 8998, Streebog, GOST R 34.10-2012 and SM2 signatures, HKDF RFC 5869, X25519 RFC 7748) and full handshake+data loopbacks for every cipher suite plus mTLS.

## Native AOT

All projects are configured for native AOT compilation:

```bash
dotnet publish -c Release --project TLSServer
```

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

- **National crypto external interop is unverified.** GOST and Chinese SM suites are KAT-verified against published standard test vectors and pass self-interop (this stack's client ↔ server), but have not been cross-tested against GmSSL / OpenSSL-GOST. In particular, this stack emits Streebog digests in the reverse byte order of RFC 6986's textual presentation, and the GOST/SM CertificateVerify hashing is internally self-consistent — byte-order conventions should be validated before relying on external interop.
- **National-suite performance is correctness-first.** AES-GCM uses hardware acceleration (~1.5 GB/s); the managed national AEADs run at tens of MB/s. GOST/SM2 EC point math uses affine coordinates (a modular inverse per point-add), adding a few hundred ms per national-suite handshake.
- The on-wire ClientHello `signature_algorithms` / `supported_groups` advertise the standard set only; national schemes/curves work in self-interop because the server selects directly.
- `max_fragment_length` (RFC 6066) is intentionally not sent (superseded by `record_size_limit`).
