namespace TLS;

using System.Security.Cryptography;

/// <summary>AEAD algorithm for a TLS 1.3 cipher suite.</summary>
public enum AeadAlgorithm
{
    AesGcm,
    ChaCha20Poly1305,
    MgmKuznyechik, // RFC 9367 / RFC 9058: tag 16, nonce 16
    MgmMagma,      // RFC 9367 / RFC 9058: tag 8,  nonce 8
    Sm4Gcm,        // RFC 8998: tag 16, nonce 12
    Sm4Ccm         // RFC 8998: tag 16, nonce 12
}

/// <summary>AEAD cipher with per-record nonce management for TLS 1.3.
/// Supports AES-GCM, ChaCha20-Poly1305, and GOST MGM (Kuznyechik/Magma).</summary>
public sealed class AeadCipher : IDisposable
{
    // RFC 8446 §5.5: per-key usage limits (encryption side).
    // Watermark = soft trigger to request KeyUpdate; HardLimit = refuse to encrypt further.
    private const ulong AesGcmRekeyWatermark = 1UL << 23;                 // 8.4M records
    private const ulong AesGcmHardLimit      = (1UL << 24) + (1UL << 23); // ≈2^24.5  (RFC 8446)
    private const ulong ChachaRekeyWatermark = 1UL << 31;                 // 2.1G records
    private const ulong ChachaHardLimit      = 1UL << 47;                 // safety margin below RFC 8446's 2^48
    private const ulong MgmRekeyWatermark    = 1UL << 38;                 // conservative GOST watermark
    private const ulong MgmHardLimit         = 1UL << 39;                 // one doubling above watermark
    // SM4-GCM/CCM share the AES-GCM structural family; reuse the AES-GCM limits.
    private const ulong Sm4HardLimit         = (1UL << 24) + (1UL << 23);

    private readonly byte[] _key;
    private readonly byte[] _iv; // nonce length: 12 (AES/ChaCha), 16 (Kuznyechik), 8 (Magma)
    private readonly AeadAlgorithm _alg;
    private readonly int _tagLen;
    private readonly Mgm? _mgm;
    private readonly Sm4Aead? _sm4;
    private readonly ChaCha20Poly1305Managed? _chachaManaged;
    private readonly AesGcmManaged? _aesManaged;
    private ulong _seqNum;

    public AeadCipher(byte[] key, byte[] iv, AeadAlgorithm alg = AeadAlgorithm.AesGcm)
    {
        _key = (byte[])key.Clone();
        _iv = (byte[])iv.Clone();
        _alg = alg;
        _seqNum = 0;
        _tagLen = alg == AeadAlgorithm.MgmMagma ? 8 : 16;
        _mgm = alg switch
        {
            AeadAlgorithm.MgmKuznyechik => new Mgm(_key, kuznyechik: true, tagLen: 16),
            AeadAlgorithm.MgmMagma => new Mgm(_key, kuznyechik: false, tagLen: 8),
            _ => null
        };
        _sm4 = alg switch
        {
            AeadAlgorithm.Sm4Gcm => new Sm4Aead(_key, ccm: false, tagLen: 16),
            AeadAlgorithm.Sm4Ccm => new Sm4Aead(_key, ccm: true, tagLen: 16),
            _ => null
        };
        // Always route ChaCha20-Poly1305 and AES-GCM through the managed wrappers —
        // no BCrypt / OpenSSL P/Invoke. BC's AesEngine still uses AES-NI when the CPU has it.
        _chachaManaged = alg == AeadAlgorithm.ChaCha20Poly1305
            ? new ChaCha20Poly1305Managed(_key)
            : null;
        _aesManaged = alg == AeadAlgorithm.AesGcm
            ? new AesGcmManaged(_key, _tagLen)
            : null;

        // Defence-in-depth: exactly one of the four backends must be wired. An unknown
        // AeadAlgorithm enum value would otherwise produce a silent NRE on Encrypt/Decrypt.
        if (_mgm == null && _sm4 == null && _chachaManaged == null && _aesManaged == null)
            throw new ArgumentException($"Unsupported AEAD algorithm: {alg}", nameof(alg));
    }

    /// <summary>AEAD tag length in bytes for this cipher (16 for AES-GCM/ChaCha/Kuznyechik, 8 for Magma).</summary>
    public int TagLength => _tagLen;

    /// <summary>Number of records encrypted/decrypted with this key.</summary>
    public ulong RecordCount => _seqNum;

    /// <summary>RFC 8446 §5.5: true once enough records have flowed to recommend a KeyUpdate.</summary>
    public bool NeedsKeyUpdate => _seqNum >= _alg switch
    {
        AeadAlgorithm.ChaCha20Poly1305 => ChachaRekeyWatermark,
        AeadAlgorithm.MgmKuznyechik or AeadAlgorithm.MgmMagma => MgmRekeyWatermark,
        _ => AesGcmRekeyWatermark
    };

    /// <summary>Encrypt plaintext with AEAD. Returns ciphertext ‖ tag.</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        EnforceHardLimit();

        // Mgm and Sm4 take byte[] — keep the alloc for those paths only. AES/ChaCha can
        // take a Span, so we stackalloc for the hot path.
        if (_mgm != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            return _mgm.Encrypt(nonce, plaintext, aad);
        }
        if (_sm4 != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            return _sm4.Encrypt(nonce, plaintext, aad);
        }

        Span<byte> nonceSpan = stackalloc byte[_iv.Length];
        BuildNonceInto(nonceSpan);
        _seqNum++;

        // Allocate one final-size buffer and encrypt directly into its two regions
        // (ciphertext slice + tag slice). Cuts the three allocations + two BlockCopy
        // calls that the old (ciphertext, tag, combined-result) pattern did.
        byte[] result = new byte[plaintext.Length + _tagLen];
        var ctSpan = result.AsSpan(0, plaintext.Length);
        var tagSpan = result.AsSpan(plaintext.Length, _tagLen);

        if (_alg == AeadAlgorithm.ChaCha20Poly1305)
            _chachaManaged!.Encrypt(nonceSpan, plaintext, ctSpan, tagSpan, aad);
        else
            _aesManaged!.Encrypt(nonceSpan, plaintext, ctSpan, tagSpan, aad);

        return result;
    }

    /// <summary>Decrypt ciphertext ‖ tag. Returns plaintext.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad)
    {
        // RFC 8446 §5.5 applies to the key, not the direction — if our peer has been
        // misbehaving and emitted records past the AEAD limit without KeyUpdate, fail
        // closed instead of silently propagating an exhausted key on the read side.
        EnforceHardLimit();

        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0)
            throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");

        if (_mgm != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            try { return _mgm.Decrypt(nonce, encrypted, aad); }
            catch (CryptographicException e)
            { throw new TlsException(AlertDescription.BadRecordMac, e.Message); }
        }
        if (_sm4 != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            try { return _sm4.Decrypt(nonce, encrypted, aad); }
            catch (CryptographicException e)
            { throw new TlsException(AlertDescription.BadRecordMac, e.Message); }
        }

        Span<byte> nonceSpan = stackalloc byte[_iv.Length];
        BuildNonceInto(nonceSpan);
        _seqNum++;

        var ciphertext = encrypted[..ctLen];
        var tag = encrypted[ctLen..];
        byte[] plaintext = new byte[ctLen];

        if (_alg == AeadAlgorithm.ChaCha20Poly1305)
            _chachaManaged!.Decrypt(nonceSpan, ciphertext, tag, plaintext, aad);
        else
            _aesManaged!.Decrypt(nonceSpan, ciphertext, tag, plaintext, aad);

        return plaintext;
    }

    /// <summary>Try to decrypt; returns false (without advancing seqNum) on authentication failure.</summary>
    public bool TryDecrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        // Same RFC 8446 §5.5 reasoning as Decrypt(): hard-fail if the peer pushes us past
        // the AEAD's per-key safety budget without KeyUpdate.
        EnforceHardLimit();

        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0) { plaintext = null; return false; }

        if (_mgm != null)
        {
            byte[] nonce = BuildNonce();
            if (_mgm.TryDecrypt(nonce, encrypted, aad, out plaintext)) { _seqNum++; return true; }
            return false;
        }
        if (_sm4 != null)
        {
            byte[] nonce = BuildNonce();
            if (_sm4.TryDecrypt(nonce, encrypted, aad, out plaintext)) { _seqNum++; return true; }
            return false;
        }

        Span<byte> nonceSpan = stackalloc byte[_iv.Length];
        BuildNonceInto(nonceSpan);
        var ciphertext = encrypted[..ctLen];
        var tag = encrypted[ctLen..];
        byte[] buf = new byte[ctLen];

        try
        {
            if (_alg == AeadAlgorithm.ChaCha20Poly1305)
                _chachaManaged!.Decrypt(nonceSpan, ciphertext, tag, buf, aad);
            else
                _aesManaged!.Decrypt(nonceSpan, ciphertext, tag, buf, aad);
            _seqNum++;
            plaintext = buf;
            return true;
        }
        catch (CryptographicException)
        {
            // AuthenticationTagMismatchException derives from CryptographicException, so
            // this single catch covers both the BCL and managed-fallback failure paths.
            plaintext = null;
            return false;
        }
    }

    // RFC 8446 §5.5: refuse to keep encrypting once the per-key record count would exceed
    // safe limits. The peer is expected to KeyUpdate well before this; we fail closed.
    private void EnforceHardLimit()
    {
        ulong limit = _alg switch
        {
            AeadAlgorithm.AesGcm           => AesGcmHardLimit,
            AeadAlgorithm.ChaCha20Poly1305 => ChachaHardLimit,
            AeadAlgorithm.MgmKuznyechik or AeadAlgorithm.MgmMagma => MgmHardLimit,
            AeadAlgorithm.Sm4Gcm or AeadAlgorithm.Sm4Ccm          => Sm4HardLimit,
            _ => ulong.MaxValue
        };
        if (_seqNum >= limit)
            throw new TlsException(AlertDescription.InternalError,
                $"{_alg} per-key record limit reached; KeyUpdate required");
    }

    /// <summary>nonce = IV XOR padded_sequence_number (legacy byte[] path for Mgm/Sm4).</summary>
    private byte[] BuildNonce()
    {
        byte[] nonce = (byte[])_iv.Clone();
        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(_seqNum >> (8 * i));
        return nonce;
    }

    /// <summary>nonce = IV XOR padded_sequence_number — fills a caller-provided Span (no heap).</summary>
    private void BuildNonceInto(Span<byte> dest)
    {
        _iv.AsSpan().CopyTo(dest);
        for (int i = 0; i < 8; i++)
            dest[dest.Length - 1 - i] ^= (byte)(_seqNum >> (8 * i));
    }

    public void Dispose()
    {
        _mgm?.Dispose();
        _chachaManaged?.Dispose();
        _aesManaged?.Dispose();
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_iv);
    }
}
