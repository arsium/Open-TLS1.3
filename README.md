# TLSServer

A complete TLS 1.3 implementation in pure C# targeting .NET 9.0. Every protocol layer — from the record framing and handshake state machine down to the elliptic-curve arithmetic and post-quantum key exchange — is written from scratch with zero external dependencies (except .NET's built-in AES-GCM and ChaCha20-Poly1305 AEAD primitives).

> **Note:** AI driven prompt project.

## Features

### Protocol

- Full TLS 1.3 (RFC 8446) handshake — client and server
- Mutual TLS (mTLS) with client certificate authentication
- PSK session resumption with NewSessionTicket
- 0-RTT early data
- Post-handshake key update (RFC 8446 Section 4.6.3)
- Post-handshake client authentication
- HelloRetryRequest with cookie support
- ALPN negotiation
- Middlebox compatibility mode (ChangeCipherSpec)
- SSLKEYLOGFILE logging (Wireshark-compatible NSS Key Log Format)

### Cryptography

| Category | Algorithms |
|---|---|
| Key Exchange | X25519, X448, ECDH P-256, ECDH P-384, **X25519MLKEM768** (hybrid post-quantum) |
| Signatures | ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, Ed25519, RSA-PSS |
| AEAD Ciphers | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| Hash / KDF | SHA-256, SHA-384, SHA-512, HKDF (RFC 5869) |
| Post-Quantum | ML-KEM-768 (FIPS 203) with NTT-based polynomial arithmetic |
| Keccak Sponge | SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 (pure managed) |
| Certificates | X.509 v3 generation, CA chaining, PKCS#12/PFX import/export |
| Compression | Certificate compression (RFC 8879) via Brotli and Zstandard |

All elliptic-curve operations (point addition, doubling, scalar multiplication) and the ML-KEM NTT/InvNTT are implemented from scratch using `System.Numerics.BigInteger` — no platform-specific or third-party crypto libraries.

### Architecture

```
TLSServer.sln
├── TLS/                  # Shared project — core TLS library
│   ├── TlsConnection.cs  # Handshake state machine (sync + async)
│   ├── RecordLayer.cs     # Record framing, AEAD encryption, fragmentation
│   ├── KeySchedule.cs     # TLS 1.3 key schedule (RFC 8446 §7)
│   ├── Ed25519.cs         # RFC 8032 signatures (extended Edwards coordinates)
│   ├── X25519.cs          # RFC 7748 Diffie-Hellman
│   ├── X448.cs            # RFC 7748 Diffie-Hellman (Goldilocks)
│   ├── MlKem768.cs        # FIPS 203 ML-KEM-768 (Kyber)
│   ├── Keccak.cs          # Keccak-f[1600] sponge (SHA3/SHAKE)
│   ├── EcdhP256.cs        # NIST P-256 ECDH
│   ├── EcdhP384.cs        # NIST P-384 ECDH
│   ├── AeadCipher.cs      # AES-GCM / ChaCha20-Poly1305 wrapper
│   ├── CertificateUtils.cs # X.509 generation, CA chaining, PFX
│   ├── Asn1.cs            # DER encoder/decoder
│   ├── Pkcs12.cs          # PFX import/export
│   ├── SessionTicket.cs   # PSK resumption store
│   ├── CertificateCompression.cs  # RFC 8879 (Brotli + Zstd)
│   ├── KeyLogger.cs       # SSLKEYLOGFILE support
│   ├── Zstd/              # Pure managed Zstandard implementation
│   └── ...
├── TLSServer/            # Synchronous server application
├── TLSClient/            # Synchronous client application
├── TLSServerAsync/       # Asynchronous server application
└── TLSClientAsync/       # Asynchronous client application
```

## Quick Start

### Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)

### Build

```bash
dotnet build TLSServer.sln
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

### Wireshark Decryption

Set the `SSLKEYLOGFILE` environment variable before running the server or client to enable key logging:

```bash
export SSLKEYLOGFILE=~/keys.log
dotnet run --project TLSServer
```

Then point Wireshark to the key log file under *Preferences > Protocols > TLS > (Pre)-Master-Secret log filename*.

## Native AOT

All projects are configured for native AOT compilation:

```bash
dotnet publish -c Release --project TLSServer
```

## RFC Compliance

| Specification | Coverage |
|---|---|
| RFC 8446 | TLS 1.3 protocol, handshake, record layer, key schedule |
| RFC 7748 | X25519 and X448 Diffie-Hellman |
| RFC 8032 | Ed25519 signatures |
| RFC 5869 | HKDF key derivation |
| RFC 8879 | Certificate compression (Brotli, Zstandard) |
| FIPS 203 | ML-KEM-768 (Module-Lattice Key Encapsulation) |
| draft-ietf-tls-ecdhe-mlkem | X25519MLKEM768 hybrid key exchange |
