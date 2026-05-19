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
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    Alpn = 16,
    CertificateCompression = 27,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    KeyShare = 51
}

public enum CipherSuite : ushort
{
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
}

public enum NamedGroup : ushort
{
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    X25519 = 0x001d,
    X448 = 0x001e,
    X25519MLKEM768 = 0x11EC
}

public enum SignatureScheme : ushort
{
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    Ed25519 = 0x0807,
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805
}

public enum AlertLevel : byte
{
    Warning = 1,
    Fatal = 2
}

public enum AlertDescription : byte
{
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InternalError = 80,
    MissingExtension = 109,
    CertificateRequired = 116,
    UnsupportedExtension = 110
}

public sealed class TlsException : Exception
{
    public AlertDescription Alert { get; }

    public TlsException(AlertDescription alert, string message) : base(message)
    {
        Alert = alert;
    }
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
