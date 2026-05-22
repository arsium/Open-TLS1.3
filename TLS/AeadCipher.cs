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
    // RFC 8446 §5.5: per-key usage limits.
    private const ulong AesGcmRekeyWatermark = 1UL << 23;          // 8.4M records — request KeyUpdate
    private const ulong AesGcmHardLimit      = (1UL << 24) + (1UL << 23); // ~2^24.5 — refuse to encrypt
    private const ulong ChachaRekeyWatermark = 1UL << 31;          // 2.1G records — request KeyUpdate
    private const ulong MgmRekeyWatermark    = 1UL << 38;          // conservative GOST rekey watermark

    private readonly byte[] _key;
    private readonly byte[] _iv; // nonce length: 12 (AES/ChaCha), 16 (Kuznyechik), 8 (Magma)
    private readonly AeadAlgorithm _alg;
    private readonly int _tagLen;
    private readonly Mgm? _mgm;
    private readonly Sm4Aead? _sm4;
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
        if (_alg == AeadAlgorithm.AesGcm && _seqNum >= AesGcmHardLimit)
            throw new TlsException(AlertDescription.InternalError,
                "AES-GCM per-key record limit exceeded; KeyUpdate required");

        byte[] nonce = BuildNonce();
        _seqNum++;

        if (_mgm != null)
            return _mgm.Encrypt(nonce, plaintext, aad);
        if (_sm4 != null)
            return _sm4.Encrypt(nonce, plaintext, aad);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[_tagLen];

        if (_alg == AeadAlgorithm.ChaCha20Poly1305)
        {
            using var chacha = new ChaCha20Poly1305(_key);
            chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        else
        {
            using var aes = new AesGcm(_key, _tagLen);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }

        byte[] result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    /// <summary>Decrypt ciphertext ‖ tag. Returns plaintext.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad)
    {
        byte[] nonce = BuildNonce();
        _seqNum++;

        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0)
            throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");

        if (_mgm != null)
        {
            try { return _mgm.Decrypt(nonce, encrypted, aad); }
            catch (CryptographicException e)
            { throw new TlsException(AlertDescription.BadRecordMac, e.Message); }
        }
        if (_sm4 != null)
        {
            try { return _sm4.Decrypt(nonce, encrypted, aad); }
            catch (CryptographicException e)
            { throw new TlsException(AlertDescription.BadRecordMac, e.Message); }
        }

        var ciphertext = encrypted[..ctLen];
        var tag = encrypted[ctLen..];
        byte[] plaintext = new byte[ctLen];

        if (_alg == AeadAlgorithm.ChaCha20Poly1305)
        {
            using var chacha = new ChaCha20Poly1305(_key);
            chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        else
        {
            using var aes = new AesGcm(_key, _tagLen);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }

        return plaintext;
    }

    /// <summary>Try to decrypt; returns false (without advancing seqNum) on authentication failure.</summary>
    public bool TryDecrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0) { plaintext = null; return false; }

        byte[] nonce = BuildNonce();

        if (_mgm != null)
        {
            if (_mgm.TryDecrypt(nonce, encrypted, aad, out plaintext)) { _seqNum++; return true; }
            return false;
        }
        if (_sm4 != null)
        {
            if (_sm4.TryDecrypt(nonce, encrypted, aad, out plaintext)) { _seqNum++; return true; }
            return false;
        }

        var ciphertext = encrypted[..ctLen];
        var tag = encrypted[ctLen..];
        byte[] buf = new byte[ctLen];

        try
        {
            if (_alg == AeadAlgorithm.ChaCha20Poly1305)
            {
                using var chacha = new ChaCha20Poly1305(_key);
                chacha.Decrypt(nonce, ciphertext, tag, buf, aad);
            }
            else
            {
                using var aes = new AesGcm(_key, _tagLen);
                aes.Decrypt(nonce, ciphertext, tag, buf, aad);
            }
            _seqNum++;
            plaintext = buf;
            return true;
        }
        catch (CryptographicException)
        {
            plaintext = null;
            return false;
        }
    }

    /// <summary>nonce = IV XOR padded_sequence_number</summary>
    private byte[] BuildNonce()
    {
        byte[] nonce = (byte[])_iv.Clone();
        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(_seqNum >> (8 * i));
        return nonce;
    }

    public void Dispose()
    {
        _mgm?.Dispose();
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_iv);
    }
}
