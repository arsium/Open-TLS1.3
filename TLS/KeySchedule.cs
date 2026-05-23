namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// TLS 1.3 key schedule (RFC 8446 §7.1).
///
///              0
///              |
///              v
///    PSK ->  HKDF-Extract = Early Secret
///              |
///        Derive-Secret(., "derived", "")
///              |
///              v
///    (EC)DHE -> HKDF-Extract = Handshake Secret
///              |
///              +---> Derive-Secret(., "c hs traffic", CH..SH) = client_handshake_traffic_secret
///              +---> Derive-Secret(., "s hs traffic", CH..SH) = server_handshake_traffic_secret
///              |
///        Derive-Secret(., "derived", "")
///              |
///              v
///    0 -> HKDF-Extract = Master Secret
///              |
///              +---> Derive-Secret(., "c ap traffic", CH..SF) = client_app_traffic_secret_0
///              +---> Derive-Secret(., "s ap traffic", CH..SF) = server_app_traffic_secret_0
/// </summary>
public sealed class KeySchedule : IDisposable
{
    private readonly HashAlgorithmName _hash;
    private readonly int _hashLen;
    private readonly int _keyLen;
    private readonly int _ivLen;

    private byte[] _earlySecret;
    private byte[] _handshakeSecret = null!;
    private byte[] _masterSecret = null!;
    private bool _disposed;

    public byte[]? ServerHandshakeTrafficSecret { get; private set; }
    public byte[]? ClientHandshakeTrafficSecret { get; private set; }
    public byte[]? ServerAppTrafficSecret { get; private set; }
    public byte[]? ClientAppTrafficSecret { get; private set; }
    public byte[]? ExporterMasterSecret { get; private set; }
    public byte[]? ResumptionMasterSecret { get; private set; }

    public HashAlgorithmName HashAlgorithm => _hash;

    /// <summary>True when the negotiated cipher suite is ChaCha20-Poly1305.</summary>
    public bool IsChaCha20 { get; }

    /// <summary>The AEAD algorithm for the negotiated cipher suite.</summary>
    public AeadAlgorithm Aead { get; }

    /// <summary>The negotiated cipher suite.</summary>
    public CipherSuite Suite { get; }

    public KeySchedule(CipherSuite suite, byte[]? psk = null)
    {
        Suite = suite;
        IsChaCha20 = suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256;

        // (hash, hashLen, keyLen, ivLen, aead)
        (_hash, _hashLen, _keyLen, _ivLen, Aead) = suite switch
        {
            CipherSuite.TLS_AES_128_GCM_SHA256 => (HashAlgorithmName.SHA256, 32, 16, 12, AeadAlgorithm.AesGcm),
            CipherSuite.TLS_AES_256_GCM_SHA384 => (HashAlgorithmName.SHA384, 48, 32, 12, AeadAlgorithm.AesGcm),
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256 => (HashAlgorithmName.SHA256, 32, 32, 12, AeadAlgorithm.ChaCha20Poly1305),
            CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L or
            CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
                => (GostKdf.Streebog256Name, 32, 32, 16, AeadAlgorithm.MgmKuznyechik),
            CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L or
            CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
                => (GostKdf.Streebog256Name, 32, 32, 8, AeadAlgorithm.MgmMagma),
            CipherSuite.TLS_SM4_GCM_SM3 => (Sm3Kdf.Sm3Name, 32, 16, 12, AeadAlgorithm.Sm4Gcm),
            CipherSuite.TLS_SM4_CCM_SM3 => (Sm3Kdf.Sm3Name, 32, 16, 12, AeadAlgorithm.Sm4Ccm),
            _ => throw new TlsException(AlertDescription.HandshakeFailure, $"Unsupported suite: {suite}")
        };

        // Early secret: PSK (or zeros if no PSK)
        byte[] ikm = psk ?? new byte[_hashLen];
        _earlySecret = Hkdf.Extract(_hash, new byte[_hashLen], ikm);
    }

    /// <summary>Derive the binder key for PSK verification (RFC 8446 §4.2.11.2).</summary>
    public byte[] DeriveBinderKey()
    {
        byte[] emptyHash = HashEmpty();
        return Hkdf.DeriveSecret(_hash, _earlySecret, "res binder", emptyHash);
    }

    /// <summary>Derive client early traffic secret for 0-RTT (RFC 8446 §7.1).</summary>
    public byte[] DeriveClientEarlyTrafficSecret(byte[] clientHelloHash)
    {
        return Hkdf.DeriveSecret(_hash, _earlySecret, "c e traffic", clientHelloHash);
    }

    /// <summary>Derive early exporter master secret (RFC 8446 §7.5).</summary>
    public byte[] DeriveEarlyExporterMasterSecret(byte[] clientHelloHash)
    {
        return Hkdf.DeriveSecret(_hash, _earlySecret, "e exp master", clientHelloHash);
    }

    /// <summary>Derive handshake traffic secrets from the (EC)DHE shared secret.</summary>
    public void DeriveHandshakeSecrets(byte[] sharedSecret, byte[] transcriptHash)
    {
        byte[] emptyHash = HashEmpty();
        byte[] derived = Hkdf.DeriveSecret(_hash, _earlySecret, "derived", emptyHash);

        _handshakeSecret = Hkdf.Extract(_hash, derived, sharedSecret);

        ClientHandshakeTrafficSecret = Hkdf.DeriveSecret(_hash, _handshakeSecret,
            "c hs traffic", transcriptHash);
        ServerHandshakeTrafficSecret = Hkdf.DeriveSecret(_hash, _handshakeSecret,
            "s hs traffic", transcriptHash);
    }

    /// <summary>Derive application traffic secrets (transcript must include server Finished).</summary>
    public void DeriveAppSecrets(byte[] transcriptHash)
    {
        byte[] emptyHash = HashEmpty();
        byte[] derived = Hkdf.DeriveSecret(_hash, _handshakeSecret, "derived", emptyHash);

        _masterSecret = Hkdf.Extract(_hash, derived, new byte[_hashLen]);

        ClientAppTrafficSecret = Hkdf.DeriveSecret(_hash, _masterSecret,
            "c ap traffic", transcriptHash);
        ServerAppTrafficSecret = Hkdf.DeriveSecret(_hash, _masterSecret,
            "s ap traffic", transcriptHash);
        ExporterMasterSecret = Hkdf.DeriveSecret(_hash, _masterSecret,
            "exp master", transcriptHash);
    }

    /// <summary>Derive resumption master secret (transcript must include client Finished).</summary>
    public void DeriveResumptionMasterSecret(byte[] fullTranscriptHash)
    {
        ResumptionMasterSecret = Hkdf.DeriveSecret(_hash, _masterSecret,
            "res master", fullTranscriptHash);
    }

    /// <summary>Export keying material (RFC 8446 §7.5).</summary>
    public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
    {
        byte[] contextHash = HashData(context);
        // Derive-Secret(exporter_master_secret, label, "")
        byte[] emptyHash = HashEmpty();
        byte[] secret = Hkdf.DeriveSecret(_hash, ExporterMasterSecret!, label, emptyHash);
        // HKDF-Expand-Label(secret, "exporter", Hash(context), length)
        return Hkdf.ExpandLabel(_hash, secret, "exporter", contextHash, length);
    }

    /// <summary>Derive PSK from resumption_master_secret + ticket nonce (RFC 8446 §4.6.1).</summary>
    public byte[] DerivePsk(byte[] ticketNonce)
    {
        return Hkdf.ExpandLabel(_hash, ResumptionMasterSecret!, "resumption", ticketNonce, _hashLen);
    }

    /// <summary>Derive write key + IV from a traffic secret.</summary>
    public (byte[] key, byte[] iv) DeriveKeyAndIv(byte[] trafficSecret)
    {
        byte[] key = Hkdf.ExpandLabel(_hash, trafficSecret, "key", Array.Empty<byte>(), _keyLen);
        byte[] iv = Hkdf.ExpandLabel(_hash, trafficSecret, "iv", Array.Empty<byte>(), _ivLen);
        return (key, iv);
    }

    /// <summary>Compute the Finished verify_data.</summary>
    public byte[] ComputeFinishedVerifyData(byte[] baseKey, byte[] transcriptHash)
    {
        byte[] finishedKey = Hkdf.ExpandLabel(_hash, baseKey, "finished",
            Array.Empty<byte>(), _hashLen);
        if (GostKdf.IsStreebog(_hash))
            return GostKdf.Hmac(finishedKey, transcriptHash);
        if (Sm3Kdf.IsSm3(_hash))
            return Sm3Kdf.Hmac(finishedKey, transcriptHash);
        if (_hash == HashAlgorithmName.SHA256) return Sha2Managed.HmacSha256(finishedKey, transcriptHash);
        if (_hash == HashAlgorithmName.SHA384) return Sha2Managed.HmacSha384(finishedKey, transcriptHash);
        if (_hash == HashAlgorithmName.SHA512) return Sha2Managed.HmacSha512(finishedKey, transcriptHash);
        throw new ArgumentException($"Unsupported HMAC hash: {_hash}");
    }

    /// <summary>Derive the next application traffic secret for KeyUpdate (RFC 8446 §7.2).</summary>
    public byte[] DeriveNextAppTrafficSecret(byte[] currentSecret)
    {
        return Hkdf.ExpandLabel(_hash, currentSecret, "traffic upd", Array.Empty<byte>(), _hashLen);
    }

    /// <summary>Update the server application traffic secret (for KeyUpdate).</summary>
    public void UpdateServerAppTrafficSecret()
    {
        ServerAppTrafficSecret = DeriveNextAppTrafficSecret(ServerAppTrafficSecret!);
    }

    /// <summary>Update the client application traffic secret (for KeyUpdate).</summary>
    public void UpdateClientAppTrafficSecret()
    {
        ClientAppTrafficSecret = DeriveNextAppTrafficSecret(ClientAppTrafficSecret!);
    }

    public int HashLen => _hashLen;

    internal byte[] HashData(byte[] data)
    {
        if (_hash == HashAlgorithmName.SHA256) return Sha2Managed.Sha256(data);
        if (_hash == HashAlgorithmName.SHA384) return Sha2Managed.Sha384(data);
        if (GostKdf.IsStreebog(_hash)) return GostKdf.Hash(data);
        if (Sm3Kdf.IsSm3(_hash)) return Sm3Kdf.Hash(data);
        throw new ArgumentException($"Unsupported hash: {_hash}");
    }

    private byte[] HashEmpty() => HashData(Array.Empty<byte>());

    /// <summary>
    /// Cryptographically zero every derived secret and master/handshake key still held by
    /// this schedule. Safe to call multiple times. Callers should invoke this when the TLS
    /// session is finished to reduce the window during which key material lingers in memory.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Zero(_earlySecret);
        Zero(_handshakeSecret);
        Zero(_masterSecret);
        Zero(ClientHandshakeTrafficSecret);
        Zero(ServerHandshakeTrafficSecret);
        Zero(ClientAppTrafficSecret);
        Zero(ServerAppTrafficSecret);
        Zero(ExporterMasterSecret);
        Zero(ResumptionMasterSecret);
    }

    private static void Zero(byte[]? buf)
    {
        if (buf != null && buf.Length > 0)
            CryptographicOperations.ZeroMemory(buf);
    }
}
