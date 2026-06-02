# OpenTls13 — Public API Reference

Pure-managed TLS 1.3 (RFC 8446) for .NET. Everything lives in the **`TLS`** namespace.

This document covers the public, consumer-facing API. There are two layers:

- **High-level wrappers** — [`TlsClient`](#tlsclient) / [`TlsServer`](#tlsserver) → [`TlsStream`](#tlsstream).
  These own the TCP socket and cover the common cases.
- **Low-level connection** — [`TlsConnection`](#tlsconnection-advanced) wraps any `System.IO.Stream`
  and exposes every knob (external PSKs, allow-lists, channel binding, exported authenticators, …).
  Use it when you need a transport other than `TcpClient`, or a feature the wrappers don't surface.

> **Conventions.** All async methods take a trailing `CancellationToken ct = default`. "Draft" marks an
> IETF Internet-Draft (not a finalized RFC) — see [RFC vs Internet-Draft](#rfc-vs-internet-draft).

---

## Contents
- [Quick start](#quick-start)
- [TlsClient](#tlsclient)
- [TlsServer](#tlsserver)
- [TlsStream](#tlsstream)
- [TlsConnection (advanced)](#tlsconnection-advanced)
- [Certificates — TlsCertificate & CertificateUtils](#certificates)
- [PSK, resumption & 0-RTT](#psk-resumption--0-rtt)
- [Encrypted Client Hello (ECH)](#encrypted-client-hello-ech)
- [Enumerations](#enumerations)
- [Defaults](#defaults)
- [RFC vs Internet-Draft](#rfc-vs-internet-draft)

---

## Quick start

```csharp
using TLS;

// --- Server ---
var ca   = CertificateUtils.GenerateCA("My CA");
var cert = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);

var server = new TlsServer(cert);
server.Listen(8443);
using TlsStream s = server.Accept();          // performs the handshake
byte[] req = s.ReadAll();
s.Write(Encoding.UTF8.GetBytes("hello"));

// --- Client ---
var client = new TlsClient { CaCertificate = ca };   // validate the server cert against this CA
using TlsStream c = client.Connect("localhost", 8443);
c.Write(Encoding.UTF8.GetBytes("ping"));
byte[] resp = c.ReadAll();
```

---

## TlsClient

`public sealed class TlsClient` — connect to a TLS 1.3 server, returns a [`TlsStream`](#tlsstream).

### Properties
| Property | Type | Default | Purpose |
|---|---|---|---|
| `HandshakeTimeoutMs` | `int` | `0` (none) | Read timeout (ms) applied during the handshake. |
| `TicketStore` | `SessionTicketStore?` | `null` | Set to enable PSK session resumption (auto store + offer). |
| `AlpnProtocols` | `string[]?` | `null` | ALPN protocols to offer (RFC 7301). |
| `PaddingBlockSize` | `int` | `0` (off) | Record padding block size (RFC 8446 §5.4). |
| `RequestOcspStapling` | `bool` | `false` | Request a stapled OCSP response (RFC 6066). |
| `CipherSuites` | `CipherSuite[]?` | `null` (stack default) | Override offered cipher suites, in preference order. |
| `NamedGroups` | `NamedGroup[]?` | `null` (stack default) | Override offered key-exchange groups. Also restricts the advertised `supported_groups`. |
| `SignatureSchemes` | `SignatureScheme[]?` | `null` (stack default) | Override the advertised `signature_algorithms`. |
| `CaCertificate` | `TlsCertificate?` | `null` | Trust anchor for the server cert. **If null and no callback, the server is NOT authenticated.** |
| `ServerCertificateValidationCallback` | `Func<byte[], IReadOnlyList<string>, bool>?` | `null` | Custom validation `(leafDer, warnings) → accept`. Authoritative when set. |
| `EchConfigList` | `byte[]?` | `null` | ECHConfigList (wire bytes, e.g. from DNS) to enable Encrypted Client Hello. |
| `GreaseEch` | `bool` | `false` | Send a GREASE ECH extension when ECH isn't configured (anti-ossification). |

### Methods
```csharp
TlsStream Connect(string host, int port, byte[]? earlyData = null);
TlsStream Connect(string host, int port, TlsCertificate clientCertificate, byte[]? earlyData = null);   // mTLS
Task<TlsStream> ConnectAsync(string host, int port, byte[]? earlyData = null, CancellationToken ct = default);
Task<TlsStream> ConnectAsync(string host, int port, TlsCertificate clientCertificate, byte[]? earlyData = null, CancellationToken ct = default);
```
`earlyData` sends 0-RTT data before the handshake completes; check `TlsStream.EarlyDataAccepted`.

---

## TlsServer

`public sealed class TlsServer : IDisposable` — listen and accept TLS 1.3 connections.

```csharp
public TlsServer(TlsCertificate certificate);
```

### Properties
| Property | Type | Default | Purpose |
|---|---|---|---|
| `RequireClientCertificate` | `bool` | `false` | Send CertificateRequest and require a client cert (mTLS). |
| `CaCertificate` | `TlsCertificate?` | `null` | CA used to verify client certificates (mTLS). |
| `HandshakeTimeoutMs` | `int` | `0` (none) | Handshake read timeout (ms). |
| `TicketEncryption` | `TicketEncryption?` | `null` | Set to enable session-ticket issuance (PSK resumption). |
| `Accept0Rtt` | `bool` | `false` | Accept 0-RTT early data from resuming clients. |
| `MaxEarlyDataSize` | `uint` | `16384` | Max 0-RTT bytes (effective only with `TicketEncryption` + `Accept0Rtt`). |
| `DefaultNewSessionTicketCount` | `int` | `2` | NewSessionTickets sent unsolicited after each handshake. |
| `AlpnProtocols` | `string[]?` | `null` | ALPN protocols accepted, in preference order. |
| `UseCertificateCompression` | `bool` | `false` | Compress the Certificate message (RFC 8879) when the client offers it. |
| `PaddingBlockSize` | `int` | `0` (off) | Record padding block size. |
| `OcspResponse` | `byte[]?` | `null` | DER OCSP response to staple when the client requests it. |
| `EchPrivateKey` | `byte[]?` | `null` | X25519 private key (32 bytes) matching the published ECHConfig — set with `EchConfigList` to accept ECH. |
| `EchConfigList` | `byte[]?` | `null` | The ECHConfigList this server publishes. |
| `AllowedCipherSuites` | `CipherSuite[]?` | `null` (accept any supported) | Allow-list restricting which suites the server will select. |
| `AllowedGroups` | `NamedGroup[]?` | `null` (accept any supported) | Allow-list restricting which key-exchange groups the server will select. |
| `AcceptedClientSignatureSchemes` | `SignatureScheme[]?` | `null` (stack default) | mTLS: schemes advertised in CertificateRequest. |

### Methods
```csharp
void Listen(int port, IPAddress? address = null);   // address defaults to IPAddress.Any
int? LocalPort { get; }                              // OS-assigned port after Listen(0)
TlsStream Accept();
Task<TlsStream> AcceptAsync(CancellationToken ct = default);
void Stop();
void Dispose();
```

---

## TlsStream

`public sealed class TlsStream : IDisposable` — the encrypted application-data channel returned by
`Connect`/`Accept`. Owns the underlying `TcpClient`.

### Properties (valid after the handshake)
| Property | Type | Notes |
|---|---|---|
| `PeerCertificate` | `byte[]?` | DER of the peer's leaf cert. **Client side: only proves key possession — apply trust policy / configure `CaCertificate`.** |
| `CertificateWarnings` | `IReadOnlyList<string>` | Advisory validity/hostname notes. Empty ≠ "validated". |
| `IsResumed` | `bool` | Established via PSK resumption. |
| `EchAccepted` | `bool` | Encrypted Client Hello was accepted. |
| `EchRetryConfigs` | `byte[]?` | If the server rejected ECH, the retry_configs to reconnect with. |
| `EarlyDataAccepted` | `bool` | 0-RTT early data was accepted by the server (client view). |
| `ReceivedEarlyData` | `byte[]?` | 0-RTT data received (server view). |
| `NegotiatedAlpn` | `string?` | Negotiated ALPN protocol. |
| `NegotiatedGroup` | `NamedGroup` | Negotiated key-exchange group (reflects HRR). |
| `NegotiatedCipherSuite` | `CipherSuite` | Negotiated cipher suite. |
| `PeerOcspResponse` | `byte[]?` | Server-stapled OCSP response. |

### Methods
```csharp
int  Read(byte[] buffer, int offset = 0, int count = -1);     // 0 = EOF (close_notify); count<0 → rest of buffer
byte[] ReadAll();                                              // one record's worth of plaintext
void Write(byte[] data, int offset = 0, int count = -1);
byte[] ExportKeyingMaterial(string label, byte[] context, int length);   // RFC 8446 §7.5 exporter
void RequestKeyUpdate(bool requestPeerUpdate = true);          // RFC 8446 §4.6.3
void RequestClientAuthentication();                            // server-side post-handshake auth (RFC 8446 §4.6.2)
void Close();                                                  // send close_notify + close TCP
void Dispose();

Task<int>   ReadAsync(byte[] buffer, int offset = 0, int count = -1, CancellationToken ct = default);
Task<byte[]> ReadAllAsync(CancellationToken ct = default);
Task WriteAsync(byte[] data, int offset = 0, int count = -1, CancellationToken ct = default);
Task RequestKeyUpdateAsync(bool requestPeerUpdate = true, CancellationToken ct = default);
Task RequestClientAuthenticationAsync(CancellationToken ct = default);
Task CloseAsync(CancellationToken ct = default);
```

---

## TlsConnection (advanced)

`public sealed class TlsConnection` — the protocol engine over an arbitrary `Stream`. The wrappers are
thin shells over this; use it directly for custom transports or features not on the wrappers (external
PSKs, channel binding, exported authenticators, the allow-lists).

```csharp
public TlsConnection(Stream stream, bool isServer,
                     TlsCertificate? certificate = null,
                     bool requireClientCert = false,
                     TlsCertificate? caCertificate = null);

void HandshakeAsClient(string? serverName = null);
void HandshakeAsServer();
Task HandshakeAsClientAsync(string? serverName = null, CancellationToken ct = default);
Task HandshakeAsServerAsync(CancellationToken ct = default);
```

### Data
```csharp
int  Read(byte[] buffer, int offset, int count);
byte[] ReadAll();
void Write(byte[] data, int offset, int count);
Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct = default);
Task WriteAsync(byte[] data, int offset, int count, CancellationToken ct = default);
```

### Configuration (call before the handshake)
```csharp
void SetAlpnProtocols(string[] protocols);
void SetOfferedCipherSuites(CipherSuite[] suites);        // client
void SetOfferedGroups(NamedGroup[] groups);               // client (also restricts supported_groups)
void SetOfferedSignatureSchemes(SignatureScheme[] schemes);
void SetAllowedCipherSuites(CipherSuite[] suites);        // server allow-list
void SetAllowedGroups(NamedGroup[] groups);               // server allow-list
void SetServerCertificateValidation(TlsCertificate? ca, Func<byte[], IReadOnlyList<string>, bool>? validator);  // client
void EnableCertificateCompression();                      // server (RFC 8879)
void RequestOcspStapling();                               // client
void SetOcspResponse(byte[] response);                    // server
void SetEarlyData(byte[] data);                           // client 0-RTT
void EnableServerTickets(TicketEncryption encryption, bool accept0Rtt = false, uint maxEarlyData = 16384, int ticketCount = 2);
void SetClientTicket(SessionTicket ticket);               // client resumption
void ImportExternalPsk(ExternalPsk psk);                  // RFC 9258 external PSK (resumption-style)
void EnableCertWithExternalPsk(ExternalPsk psk);          // draft-ietf-tls-8773bis (cert + external PSK)
void SetEchConfigs(EncryptedClientHello.EchConfig[] configs);   // client ECH / server accept
void SetGreaseEch();                                      // client
void SetEchPrivateKey(byte[] privateKey);                 // server ECH
```

### Post-handshake operations
```csharp
byte[] ExportKeyingMaterial(string label, byte[] context, int length);       // RFC 5705 / 8446 §7.5
byte[] GetChannelBinding(ChannelBindingType bindingType);                     // RFC 9266
byte[] ExportAuthenticator(TlsCertificate certificate, byte[] context, bool isServer = true);          // RFC 9261
bool   VerifyExportedAuthenticator(byte[] authenticator, byte[] context, bool isServer = true, TlsCertificate? caCertificate = null);
void   RequestPostHandshakeAuth();                                            // server (RFC 8446 §4.6.2)
void   SendKeyUpdate(bool requestUpdate);                                     // RFC 8446 §4.6.3
Task   RequestPostHandshakeAuthAsync(CancellationToken ct = default);
Task   SendKeyUpdateAsync(bool requestUpdate, CancellationToken ct = default);
```

### State (after the handshake)
`IsResumed`, `EarlyDataAccepted`, `NegotiatedAlpn`, `NegotiatedGroup`, `NegotiatedCipherSuite`,
`UsedCertWithExternalPsk` (draft-8773bis mode engaged), `PeerCertificateData`, `PeerOcspResponse`,
`CertificateWarnings`, `EchAccepted`, `EchRetryConfigs`, `ReceivedEarlyData`, `IsHandshakeComplete`.

---

## Certificates

### TlsCertificate
```csharp
public sealed class TlsCertificate
{
    public byte[] DerData { get; init; }              // X.509 DER
    public byte[] PrivateKey { get; init; }           // EC: 32-byte scalar | RSA: PKCS#1 DER
    public byte[] PublicKey { get; init; }            // EC: 65-byte uncompressed | RSA: PKCS#1 DER
    public SignatureScheme SignatureAlgorithm { get; init; }
    public byte[][]? ChainCertificates { get; init; } // intermediate chain (leaf-to-root order), optional
}

public enum CertificateProfile { CA, Server, Client }
```

### CertificateUtils (static)
Generation & issuance:
```csharp
TlsCertificate GenerateSelfSigned(string commonName, int validDays = 365);              // EC P-256
TlsCertificate GenerateCA(string commonName, int validDays = 3650);                      // EC CA
TlsCertificate IssueCertificate(string commonName, TlsCertificate ca, CertificateProfile profile, int validDays = 365);
TlsCertificate GenerateSelfSignedRsa(string commonName, int validDays = 365, int keySize = 2048);
TlsCertificate GenerateCARsa(string commonName, int validDays = 3650, int keySize = 2048);
TlsCertificate IssueCertificateRsa(string commonName, TlsCertificate ca, CertificateProfile profile, int validDays = 365);
TlsCertificate IssueGostCertificate(string commonName, TlsCertificate ca, CertificateProfile profile, SignatureScheme scheme = SignatureScheme.Gostr34102012_256a, int validDays = 365);
TlsCertificate IssueSm2Certificate(string commonName, TlsCertificate ca, CertificateProfile profile, int validDays = 365);
TlsCertificate IssueMlDsaCertificate(string commonName, TlsCertificate ca, CertificateProfile profile, SignatureScheme scheme = SignatureScheme.MlDsa65, int validDays = 365);  // FIPS 204 / draft
```
Validation, import/export, parsing:
```csharp
bool VerifyChain(TlsCertificate cert, TlsCertificate ca);
byte[] ExportPfx(TlsCertificate cert, string password, TlsCertificate? ca = null);
TlsCertificate ImportPfx(byte[] pfxData, string password);
string ToPem(byte[] der, string label = "CERTIFICATE");
string PrivateKeyToPem(TlsCertificate cert);
string ExportPemBundle(TlsCertificate cert, TlsCertificate? ca = null);
List<(string label, byte[] data)> ParsePemBlocks(string pem);
byte[][] ImportPemCertificates(string pem);
TlsCertificate ImportPem(string pem);
(byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ImportPrivateKeyPem(string pem);
(byte[] publicKey, SignatureScheme sigAlg) ParseCertificatePublicKey(byte[] certDer);
(DateTime notBefore, DateTime notAfter) ParseCertificateValidity(byte[] certDer);
List<string> ParseCertificateSAN(byte[] certDer);
OcspStatus VerifyOcspResponse(byte[] ocspResponseDer, byte[] certDer, TlsCertificate caCert);
byte[] Sign(byte[] data, byte[] privateKey, byte[] publicKey, SignatureScheme scheme);
bool   Verify(byte[] data, byte[] signature, byte[] publicKey, SignatureScheme scheme);
```

---

## PSK, resumption & 0-RTT

```csharp
public sealed class SessionTicket            // a stored resumption ticket
{
    public byte[] Ticket; public byte[] ResumptionSecret; public CipherSuite CipherSuite;
    public DateTime IssuedAt; public uint LifetimeSeconds; public uint AgeAdd;
    public uint MaxEarlyDataSize; public string? ServerName;     // all { get; init; }
}

public sealed class SessionTicketStore       // client-side; assign to TlsClient.TicketStore
{
    void Add(string serverName, SessionTicket ticket);
    SessionTicket? Get(string serverName);   // single-use; prunes expired
}

public sealed class TicketEncryption         // server-side; assign to TlsServer.TicketEncryption
{
    public TicketEncryption(byte[]? key = null);   // 32-byte AES-256-GCM key; random if null
    void RotateKey(byte[]? newKey = null);         // old keys retained for decrypt
}

public sealed class ExternalPsk              // RFC 9258 external PSK
{
    public byte[] Identity { get; init; }
    public byte[] Key { get; init; }
    public CipherSuite Suite { get; init; }        // determines the hash; both peers must match
    public uint MaxEarlyDataSize { get; init; }
}
```

**Resumption:** client sets `TicketStore`, server sets `TicketEncryption` — tickets are issued and
offered automatically. **0-RTT:** client passes `earlyData` to `Connect`; server sets `Accept0Rtt = true`.
**External PSK:** use `TlsConnection.ImportExternalPsk` (PSK-only auth) or `EnableCertWithExternalPsk`
(cert + PSK, draft-8773bis).

---

## Encrypted Client Hello (ECH)

RFC 9849. **Client:** set `TlsClient.EchConfigList` to the server's published ECHConfigList (wire bytes,
typically from a DNS HTTPS/SVCB record). **Server:** set `EchPrivateKey` (X25519 private) + `EchConfigList`.

```csharp
public static class EncryptedClientHello
{
    public sealed class EchConfig
    {
        public byte ConfigId; public ushort KemId; public byte[] PublicKey;
        public (ushort Kdf, ushort Aead)[] CipherSuites; public byte MaxNameLen;
        public byte[] PublicName; public byte[] RawBytes; public string PublicNameString;  // { get; init; }
    }

    EchConfig[] ParseEchConfigList(byte[] list);
    byte[] BuildEchConfig(byte configId, byte[] publicKey, /* … */);   // build one ECHConfig (publicKey = X25519 public)
    byte[] BuildEchConfigList(params byte[][] configs);                // concatenate into an ECHConfigList
}
```
The `EchConfig.PublicKey` must correspond to the server's `EchPrivateKey`.

---

## Enumerations

### CipherSuite (`: ushort`)
Standard (RFC 8446): `TLS_AES_128_GCM_SHA256` (0x1301), `TLS_AES_256_GCM_SHA384` (0x1302),
`TLS_CHACHA20_POLY1305_SHA256` (0x1303), `TLS_AES_128_CCM_SHA256` (0x1304), `TLS_AES_128_CCM_8_SHA256` (0x1305).
**Draft:** `TLS_AEGIS_256_SHA512` (0x1306), `TLS_AEGIS_128L_SHA256` (0x1307).
National: `TLS_SM4_GCM_SM3` (0x00C6), `TLS_SM4_CCM_SM3` (0x00C7),
`TLS_GOSTR341112_256_WITH_{KUZNYECHIK,MAGMA}_MGM_{L,S}` (0xC103–0xC106).

### NamedGroup (`: ushort`)
ECDHE: `Secp256r1`, `Secp384r1`, `Secp521r1`, `X25519`, `X448`. FFDHE: `Ffdhe2048…Ffdhe8192`.
National: `Curvesm2`, `GC256A…GC256D`, `GC512A…GC512C`.
Hybrid PQ (draft): `X25519MLKEM768` (0x11EC), `SecP256r1MLKEM768` (0x11EB), `SecP384r1MLKEM1024` (0x11ED).

### SignatureScheme (`: ushort`)
ECDSA: `EcdsaSecp256r1Sha256`, `EcdsaSecp384r1Sha384`, `EcdsaSecp521r1Sha512`.
RSA: `RsaPssRsaeSha256/384/512`, `RsaPssPssSha256/384/512`, `RsaPkcs1Sha256/384/512` (legacy, RFC 9963).
EdDSA: `Ed25519`. National: `Sm2Sm3`, `Gostr34102012_256a…d`, `Gostr34102012_512a…c`.
**PQ (draft):** `MlDsa44` (0x0904), `MlDsa65` (0x0905), `MlDsa87` (0x0906).

### ChannelBindingType
`TlsFinished`, `TlsUnique`, `TlsServerEndPoint`, `TlsExporter` (RFC 9266). For TLS 1.3 prefer `TlsExporter`.

### CertificateProfile
`CA`, `Server`, `Client`.

---

## Defaults

| Dimension | Default |
|---|---|
| Protocol | TLS 1.3 only (1.2 and below rejected). |
| Client cipher suites offered | AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM. (AEGIS/GOST/SM opt-in via `CipherSuites`.) |
| Client groups | X25519MLKEM768, X25519, X448, P-256, P-384 (key_shares); `supported_groups` also advertises the two extra hybrids. |
| Client signature schemes | ECDSA P-256/P-384, Ed25519, RSA-PSS, ML-DSA-44/65/87. |
| Server | Accepts any cipher suite / group it supports (use `AllowedCipherSuites` / `AllowedGroups` to restrict). |
| Server-cert validation (client) | **Permissive** unless `CaCertificate` or a callback is set. |
| Resumption, 0-RTT, mTLS, ECH, cert compression, padding, post-handshake auth, cert+external-PSK | **Off** (opt-in). |

---

## RFC vs Internet-Draft

Finalized RFCs implemented here include 8446 (TLS 1.3), 8447/8449, 8879 (cert compression), 9258 (external
PSK), 9261 (exported authenticators), 9266 (channel binding), 9367 (GOST), 8998 (SM), 9849 (ECH), 5705/7301/6066.

The following carry **Internet-Draft** TLS code points — **work in progress, not finalized RFCs**; pin both
peers to the same draft revision and treat as experimental:

- **AEGIS** cipher suites — `draft-denis-tls-aegis` / `draft-irtf-cfrg-aegis-aead`.
- **ML-DSA in TLS** — `draft-ietf-tls-mldsa` (the algorithm is final in FIPS 204 and its cert encoding in
  RFC 9881; only the TLS signature-scheme code points are draft).
- **Hybrid PQ key exchange** — `draft-ietf-tls-ecdhe-mlkem` (X25519MLKEM768 etc.).
- **Certificate + external PSK** — `draft-ietf-tls-8773bis` (`EnableCertWithExternalPsk`).

---

*Generated for OpenTls13 1.6.0. See `changelog.txt` for version history and `README.md` for a feature
overview and security notes.*
