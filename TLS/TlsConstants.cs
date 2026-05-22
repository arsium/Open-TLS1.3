namespace TLS;

/// <summary>TLS 1.3 protocol constants and enumerations.</summary>

public enum ContentType : byte
{
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
}

public enum HandshakeType : byte
{
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CompressedCertificate = 25,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254
}

public enum ExtensionType : ushort
{
    ServerName = 0,                     // RFC 6066 §3
    MaxFragmentLength = 1,              // RFC 6066 §4
    ClientCertificateUrl = 2,           // RFC 6066 §5
    TrustedCaKeys = 3,                  // RFC 6066 §6
    TruncatedHmac = 4,                  // RFC 6066 §7
    StatusRequest = 5,                  // RFC 6066 §8
    UserMapping = 6,                    // RFC 4681
    ClientAuthz = 7,                    // RFC 5878
    ServerAuthz = 8,                    // RFC 5878
    CertType = 9,                       // RFC 6091
    SupportedGroups = 10,               // RFC 8422/7919
    EcPointFormats = 11,                // RFC 8422
    Srp = 12,                           // RFC 5054
    SignatureAlgorithms = 13,           // RFC 8446 §4.2.3
    UseSrtp = 14,                       // RFC 5764
    Heartbeat = 15,                     // RFC 6520
    Alpn = 16,                          // RFC 7301
    StatusRequestV2 = 17,               // RFC 6961
    SignedCertificateTimestamp = 18,    // RFC 6962
    ClientCertificateType = 19,         // RFC 7250
    ServerCertificateType = 20,         // RFC 7250
    Padding = 21,                       // RFC 7685
    EncryptThenMac = 22,                // RFC 7366
    ExtendedMasterSecret = 23,          // RFC 7627
    TokenBinding = 24,                  // RFC 8472
    CachedInfo = 25,                    // RFC 7924
    TlsLts = 26,                        // draft-gutmann-tls-lts
    CertificateCompression = 27,        // RFC 8879
    RecordSizeLimit = 28,               // RFC 8449
    PwdProtect = 29,                    // RFC 8492
    PwdClear = 30,                      // RFC 8492
    PasswordSalt = 31,                  // RFC 8492
    SessionTicket = 35,                 // RFC 5077/8447
    PreSharedKey = 41,                  // RFC 8446 §4.2.11
    EarlyData = 42,                     // RFC 8446 §4.2.10
    SupportedVersions = 43,             // RFC 8446 §4.2.1
    Cookie = 44,                        // RFC 8446 §4.2.2
    PskKeyExchangeModes = 45,           // RFC 8446 §4.2.9
    CertificateAuthorities = 47,        // RFC 8446 §4.2.4
    OidFilters = 48,                    // RFC 8446 §4.2.5
    PostHandshakeAuth = 49,             // RFC 8446 §4.2.6
    SignatureAlgorithmsCert = 50,       // RFC 8446 §4.2.3
    KeyShare = 51,                      // RFC 8446 §4.2.8
    ConnectionId = 53,                  // RFC 9146
    ExternalIdHash = 55,                // RFC 8844
    ExternalSessionId = 56,             // RFC 8844
    QuicTransportParameters = 57,       // RFC 9001 §8.2
    TicketRequest = 58,                 // RFC 9149 §3
    DnsmasqSharedSecret = 59,           // Local use
    EncryptedClientHello = 65037        // RFC 9849 (for Phase C)
}

public enum CipherSuite : ushort
{
    // TLS 1.3 Standard Cipher Suites (RFC 8446)
    TLS_AES_128_GCM_SHA256 = 0x1301,           // RFC 8446 §B.4
    TLS_AES_256_GCM_SHA384 = 0x1302,           // RFC 8446 §B.4
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,     // RFC 8446 §B.4
    TLS_AES_128_CCM_SHA256 = 0x1304,           // RFC 8446 §B.4
    TLS_AES_128_CCM_8_SHA256 = 0x1305,         // RFC 8446 §B.4

    // Additional TLS 1.3 Cipher Suites
    TLS_AEGIS_128L_SHA256 = 0x1306,            // RFC 9380
    TLS_AEGIS_256_SHA512 = 0x1307,             // RFC 9380

    // Chinese National Standard (RFC 8998) - for Phase D
    TLS_SM4_GCM_SM3 = 0x00C6,                  // RFC 8998 §6
    TLS_SM4_CCM_SM3 = 0x00C7,                  // RFC 8998 §6

    // GOST Russian Standard (RFC 9367) - MGM AEAD suites for TLS 1.3
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = 0xC103,       // RFC 9367
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = 0xC104,            // RFC 9367
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = 0xC105,       // RFC 9367
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = 0xC106             // RFC 9367
}

public enum NamedGroup : ushort
{
    // Elliptic Curves (RFC 8422, 7919)
    Secp256r1 = 0x0017,                        // RFC 8422 §5.1.1
    Secp384r1 = 0x0018,                        // RFC 8422 §5.1.1
    Secp521r1 = 0x0019,                        // RFC 8422 §5.1.1
    X25519 = 0x001d,                           // RFC 7748 / RFC 8446 §4.2.7
    X448 = 0x001e,                             // RFC 7748 / RFC 8446 §4.2.7

    // Finite Field Diffie-Hellman (RFC 7919)
    Ffdhe2048 = 0x0100,                        // RFC 7919 §4
    Ffdhe3072 = 0x0101,                        // RFC 7919 §4
    Ffdhe4096 = 0x0102,                        // RFC 7919 §4
    Ffdhe6144 = 0x0103,                        // RFC 7919 §4
    Ffdhe8192 = 0x0104,                        // RFC 7919 §4

    // Chinese National Standard (RFC 8998) - for Phase D
    Curvesm2 = 0x0029,                         // RFC 8998 / IANA curveSM2 (41)

    // GOST Russian Standard (RFC 9367) - GOST curves
    GC256A = 0x0022,                           // RFC 9367 id-tc26-gost-3410-2012-256-paramSetA
    GC256B = 0x0023,                           // RFC 9367 id-GostR3410-2001-CryptoPro-A-ParamSet
    GC256C = 0x0024,                           // RFC 9367 id-GostR3410-2001-CryptoPro-B-ParamSet
    GC256D = 0x0025,                           // RFC 9367 id-GostR3410-2001-CryptoPro-C-ParamSet
    GC512A = 0x0026,                           // RFC 9367 id-tc26-gost-3410-12-512-paramSetA
    GC512B = 0x0027,                           // RFC 9367 id-tc26-gost-3410-12-512-paramSetB
    GC512C = 0x0028,                           // RFC 9367 id-tc26-gost-3410-2012-512-paramSetC

    // Post-Quantum (Hybrid)
    X25519MLKEM768 = 0x11EC,                   // IANA assigned
    P256MLKEM768 = 0x11ED,                     // IANA assigned
    X448MLKEM1024 = 0x11EE                     // IANA assigned
}

public enum SignatureScheme : ushort
{
    // Legacy RSASSA-PKCS1-v1_5 (RFC 9963 §3 - for Phase B3)
    RsaPkcs1Sha256 = 0x0401,                   // RFC 9963 §3
    RsaPkcs1Sha384 = 0x0501,                   // RFC 9963 §3
    RsaPkcs1Sha512 = 0x0601,                   // RFC 9963 §3

    // ECDSA (RFC 8446 §4.2.3)
    EcdsaSecp256r1Sha256 = 0x0403,             // RFC 8446 §4.2.3
    EcdsaSecp384r1Sha384 = 0x0503,             // RFC 8446 §4.2.3
    EcdsaSecp521r1Sha512 = 0x0603,             // RFC 8446 §4.2.3

    // RSA-PSS (RFC 8446 §4.2.3)
    RsaPssRsaeSha256 = 0x0804,                 // RFC 8446 §4.2.3
    RsaPssRsaeSha384 = 0x0805,                 // RFC 8446 §4.2.3
    RsaPssRsaeSha512 = 0x0806,                 // RFC 8446 §4.2.3

    // Edwards-curve Digital Signature Algorithm (RFC 8446 §4.2.3)
    Ed25519 = 0x0807,                          // RFC 8032 / RFC 8446 §4.2.3
    Ed448 = 0x0808,                            // RFC 8032 / RFC 8446 §4.2.3

    // RSA-PSS with PSS keys (RFC 8446 §4.2.3)
    RsaPssPssSha256 = 0x0809,                  // RFC 8446 §4.2.3
    RsaPssPssSha384 = 0x080a,                  // RFC 8446 §4.2.3
    RsaPssPssSha512 = 0x080b,                  // RFC 8446 §4.2.3

    // Chinese National Standard (RFC 8998) - for Phase D
    Sm2Sm3 = 0x0708,                          // RFC 8998 §4.2.2

    // GOST Russian Standard (RFC 9367) - for Option 2
    Gostr34102012_256a = 0x0709,              // RFC 9367 GOST R 34.10-2012 256-bit, paramSetA
    Gostr34102012_256b = 0x070A,              // RFC 9367
    Gostr34102012_256c = 0x070B,              // RFC 9367
    Gostr34102012_256d = 0x070C,              // RFC 9367
    Gostr34102012_512a = 0x070D,              // RFC 9367 GOST R 34.10-2012 512-bit, paramSetA
    Gostr34102012_512b = 0x070E,              // RFC 9367
    Gostr34102012_512c = 0x070F               // RFC 9367
}

public enum AlertLevel : byte
{
    Warning = 1,
    Fatal = 2
}

public enum AlertDescription : byte
{
    CloseNotify = 0,                           // RFC 8446 §6.1
    UnexpectedMessage = 10,                    // RFC 8446 §6.2
    BadRecordMac = 20,                         // RFC 8446 §6.2
    RecordOverflow = 22,                       // RFC 8446 §6.2
    HandshakeFailure = 40,                     // RFC 8446 §6.2
    BadCertificate = 42,                       // RFC 8446 §6.2
    UnsupportedCertificate = 43,               // RFC 8446 §6.2
    CertificateRevoked = 44,                   // RFC 8446 §6.2
    CertificateExpired = 45,                   // RFC 8446 §6.2
    CertificateUnknown = 46,                   // RFC 8446 §6.2
    IllegalParameter = 47,                     // RFC 8446 §6.2
    UnknownCa = 48,                            // RFC 8446 §6.2
    AccessDenied = 49,                         // RFC 8446 §6.2
    DecodeError = 50,                          // RFC 8446 §6.2
    DecryptError = 51,                         // RFC 8446 §6.2
    ProtocolVersion = 70,                      // RFC 8446 §6.2
    InsufficientSecurity = 71,                 // RFC 8446 §6.2
    InternalError = 80,                        // RFC 8446 §6.2
    InappropriateFallback = 86,                // RFC 7507
    UserCanceled = 90,                         // RFC 8446 §6.2
    MissingExtension = 109,                    // RFC 8446 §6.2
    UnsupportedExtension = 110,                // RFC 8446 §6.2
    UnrecognizedName = 112,                    // RFC 6066 §3 — server received unknown SNI
    BadCertificateStatusResponse = 113,        // RFC 6066 §8
    UnknownPskIdentity = 115,                  // RFC 8446 §6.2
    CertificateRequired = 116,                 // RFC 8446 §6.2
    NoApplicationProtocol = 120                // RFC 7301 §3.2 — ALPN no overlap
}

/// <summary>OCSP response status for a certificate.</summary>
public enum OcspStatus { Good, Revoked, Unknown, InvalidResponse }

/// <summary>State machine for post-handshake client authentication flow.</summary>
public enum PostHsAuthState
{
    None,
    AwaitingCertificate,
    AwaitingCertificateVerify,
    AwaitingFinished
}

public sealed class TlsException : Exception
{
    public AlertDescription Alert { get; }

    public TlsException(AlertDescription alert, string message) : base(message)
    {
        Alert = alert;
    }
}

/// <summary>TLS channel binding types (RFC 9266).</summary>
public enum ChannelBindingType
{
    TlsFinished = 0,
    TlsUnique = 1,
    TlsServerEndPoint = 2,
    TlsExporter = 3
}

/// <summary>External PSK information for RFC 9258 PSK importer.</summary>
public sealed class ExternalPsk
{
    public byte[] Identity { get; init; } = null!;
    public byte[] Key { get; init; } = null!;
    public CipherSuite Suite { get; init; }
    public uint MaxEarlyDataSize { get; init; }
}

public static class TlsConst
{
    public const ushort LegacyVersion = 0x0303;
    public const ushort Tls13Version = 0x0304;
    public const ushort RecordLegacyVersion = 0x0301;
    public const int MaxPlaintextLength = 16384;
    public const int MaxCiphertextLength = 16384 + 256;
    public const int AeadTagLength = 16;
}
