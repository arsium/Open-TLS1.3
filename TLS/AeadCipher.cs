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
    Sm4Ccm,        // RFC 8998: tag 16, nonce 12
    Aegis128L,     // draft-denis-tls-aegis: tag 16, nonce 16
    Aegis256       // draft-denis-tls-aegis: tag 16, nonce 32
}

/// <summary>AEAD cipher with per-record nonce management for TLS 1.3.
/// Supports AES-GCM, ChaCha20-Poly1305, and GOST MGM (Kuznyechik/Magma).</summary>
public sealed class AeadCipher : IDisposable
{
    // RFC 8446 §5.5: per-key usage limits (encryption side).
    // Watermark = soft trigger to request KeyUpdate; HardLimit = refuse to encrypt further.
    private const ulong AesGcmRekeyWatermark = 1UL << 23;                 // 8.4M records
    private const ulong AesGcmHardLimit      = 23_726_566;               // 2^24.5, the RFC 8446 §5.5 ceiling
    private const ulong ChachaRekeyWatermark = 1UL << 31;                 // 2.1G records
    private const ulong ChachaHardLimit      = 1UL << 47;                 // safety margin below RFC 8446's 2^48
    private const ulong MgmRekeyWatermark    = 1UL << 38;                 // conservative GOST watermark
    private const ulong MgmHardLimit         = 1UL << 39;                 // one doubling above watermark
    // SM4-GCM/CCM share the AES-GCM structural family; reuse the AES-GCM limit (2^24.5).
    private const ulong Sm4HardLimit         = 23_726_566;
    // AEGIS (draft-denis-tls-aegis §4): a KeyUpdate MUST happen before 2^48 records; fail closed below that.
    private const ulong AegisRekeyWatermark  = 1UL << 40;
    private const ulong AegisHardLimit       = 1UL << 47;

    private readonly byte[] _key;
    private readonly byte[] _iv; // nonce length: 12 (AES/ChaCha), 16 (Kuznyechik), 8 (Magma)
    private readonly AeadAlgorithm _alg;
    private readonly int _tagLen;
    private Mgm? _mgm;           // GOST: rebuilt per TLSTREE leaf (see EnsureGostRecordKey)
    private readonly Sm4Aead? _sm4;
    private readonly AegisAead? _aegis;
    private readonly ChaCha20Poly1305Managed? _chachaManaged;
    private readonly AesGcmManaged? _aesManaged;
    private ulong _seqNum;

    // RFC 9367 §4.1.2/§4.1.3 GOST external re-keying (TLSTREE) state — active only for MGM suites.
    private readonly bool _useTlsTree;
    private readonly ulong _c1, _c2, _c3; // per-suite TLSTREE masks (Table 1)
    private readonly ulong _gostSnmax;    // per-suite max records under one traffic key (SNMAX)
    private ulong _gostLeaf;              // (seqnum & C_3) of the currently-built _mgm
    private bool _gostMgmBuilt;

    public AeadCipher(byte[] key, byte[] iv, AeadAlgorithm alg = AeadAlgorithm.AesGcm, CipherSuite suite = default)
    {
        _key = (byte[])key.Clone();
        _iv = (byte[])iv.Clone();
        _alg = alg;
        _seqNum = 0;
        _tagLen = alg == AeadAlgorithm.MgmMagma ? 8 : 16;

        if (alg is AeadAlgorithm.MgmKuznyechik or AeadAlgorithm.MgmMagma)
        {
            // GOST MGM record keys are re-derived per record from the traffic key via TLSTREE
            // (RFC 9367 §4.1); the per-suite masks + SNMAX come from §4.1.2/§4.1.3. _mgm is built
            // lazily in EnsureGostRecordKey when the leaf (seqnum & C_3) first appears or changes.
            _useTlsTree = true;
            (_c1, _c2, _c3, _gostSnmax) = GostTlsTreeParams(suite);
        }
        _sm4 = alg switch
        {
            AeadAlgorithm.Sm4Gcm => new Sm4Aead(_key, ccm: false, tagLen: 16),
            AeadAlgorithm.Sm4Ccm => new Sm4Aead(_key, ccm: true, tagLen: 16),
            _ => null
        };
        _aegis = alg switch
        {
            AeadAlgorithm.Aegis128L => new AegisAead(_key, is256: false),
            AeadAlgorithm.Aegis256 => new AegisAead(_key, is256: true),
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

        // Defence-in-depth: exactly one backend must be wired (GOST counts via _useTlsTree). An
        // unknown AeadAlgorithm enum value would otherwise produce a silent NRE on Encrypt/Decrypt.
        if (!_useTlsTree && _sm4 == null && _chachaManaged == null && _aesManaged == null && _aegis == null)
            throw new ArgumentException($"Unsupported AEAD algorithm: {alg}", nameof(alg));
    }

    // RFC 9367 §4.1.2 Table 1 (TLSTREE C_1/C_2/C_3) + §4.1.3 (SNMAX), per GOST cipher suite.
    private static (ulong c1, ulong c2, ulong c3, ulong snmax) GostTlsTreeParams(CipherSuite suite) => suite switch
    {
        CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L =>
            (0xf800000000000000UL, 0xfffffff000000000UL, 0xffffffffffffe000UL, ulong.MaxValue),   // 2^64-1
        CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L =>
            (0xffe0000000000000UL, 0xffffffffc0000000UL, 0xffffffffffffff80UL, ulong.MaxValue),   // 2^64-1
        CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S =>
            (0xffffffffe0000000UL, 0xffffffffffff0000UL, 0xfffffffffffffff8UL, (1UL << 42) - 1),  // 2^42-1
        CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S =>
            (0xfffffffffc000000UL, 0xffffffffffffe000UL, 0xffffffffffffffffUL, (1UL << 39) - 1),  // 2^39-1
        _ => throw new ArgumentException($"GOST MGM AEAD requires a GOST cipher suite, got {suite}", nameof(suite))
    };

    // Re-derive the per-record MGM key when the TLSTREE leaf (seqnum & C_3) changes (RFC 9367 §4.1).
    // Within a leaf the key is constant, so the GrasshopperManaged/MagmaManaged schedule is reused.
    private void EnsureGostRecordKey()
    {
        ulong leaf = _seqNum & _c3;
        if (_gostMgmBuilt && _gostLeaf == leaf) return;
        _mgm?.Dispose();
        byte[] recordKey = GostKdf.TlsTree(_key, _seqNum, _c1, _c2, _c3);
        _mgm = new Mgm(recordKey, kuznyechik: _alg == AeadAlgorithm.MgmKuznyechik, tagLen: _tagLen);
        _gostLeaf = leaf;
        _gostMgmBuilt = true;
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
        AeadAlgorithm.Aegis128L or AeadAlgorithm.Aegis256 => AegisRekeyWatermark,
        _ => AesGcmRekeyWatermark
    };

    /// <summary>Encrypt plaintext with AEAD. Returns a freshly-allocated ciphertext||tag byte[].
    /// On the hot record-layer path prefer <see cref="EncryptInto"/> with a pooled output buffer
    /// — that's where the per-record allocation actually matters.</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        byte[] result = new byte[plaintext.Length + _tagLen];
        EncryptInto(plaintext, aad, result);
        return result;
    }

    /// <summary>Encrypt directly into a caller-provided buffer (typically rented from
    /// <see cref="System.Buffers.ArrayPool{T}"/>). <c>output.Length</c> MUST equal
    /// <c>plaintext.Length + TagLength</c>. Layout is ciphertext||tag, matching what
    /// every underlying AEAD impl produces.</summary>
    // Per-record stackalloc nonce (12-16 B) is always fully written by BuildNonceInto
    // before any read, so skipping the JIT-emitted localloc zeroing is safe.
    [System.Runtime.CompilerServices.SkipLocalsInit]
    public void EncryptInto(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> output)
    {
        EnforceHardLimit();
        if (_useTlsTree) EnsureGostRecordKey();
        if (output.Length != plaintext.Length + _tagLen)
            throw new ArgumentException($"output must be plaintext.Length + {_tagLen} bytes");

        if (_mgm != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            _mgm.EncryptInto(nonce, plaintext, output, aad);
            return;
        }
        if (_sm4 != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            _sm4.EncryptInto(nonce, plaintext, output, aad);
            return;
        }
        if (_aegis != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            _aegis.EncryptInto(nonce, plaintext, output, aad);
            return;
        }

        Span<byte> nonceSpan = stackalloc byte[_iv.Length];
        BuildNonceInto(nonceSpan);
        _seqNum++;

        if (_alg == AeadAlgorithm.ChaCha20Poly1305)
            _chachaManaged!.Encrypt(nonceSpan, plaintext, output, aad);
        else
            _aesManaged!.Encrypt(nonceSpan, plaintext, output, aad);
    }

    /// <summary>Decrypt ciphertext ‖ tag. Returns a freshly-allocated plaintext byte[].
    /// Prefer <see cref="DecryptInto"/> on the hot record-layer path.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad)
    {
        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0)
            throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");
        byte[] plaintext = new byte[ctLen];
        DecryptInto(encrypted, aad, plaintext);
        return plaintext;
    }

    /// <summary>Decrypt directly into a caller-provided buffer. <c>plaintext.Length</c> MUST
    /// equal <c>encrypted.Length - TagLength</c>. Throws on tag mismatch (same exception types
    /// as <see cref="Decrypt"/>).</summary>
    // Same SkipLocalsInit reasoning as EncryptInto.
    [System.Runtime.CompilerServices.SkipLocalsInit]
    public void DecryptInto(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, Span<byte> plaintext)
    {
        // RFC 8446 §5.5: applies to the key not the direction — fail closed if the peer
        // pushed us past the AEAD safety budget without KeyUpdate.
        EnforceHardLimit();
        if (_useTlsTree) EnsureGostRecordKey();

        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0)
            throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");
        if (plaintext.Length != ctLen)
            throw new ArgumentException($"plaintext must be encrypted.Length - {_tagLen} bytes");

        if (_mgm != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            try
            {
                if (!_mgm.TryDecryptInto(nonce, encrypted, plaintext, aad))
                    throw new TlsException(AlertDescription.BadRecordMac, "MGM authentication tag mismatch");
            }
            catch (CryptographicException e)
            { throw new TlsException(AlertDescription.BadRecordMac, e.Message); }
            return;
        }
        if (_sm4 != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            try
            {
                if (!_sm4.TryDecryptInto(nonce, encrypted, plaintext, aad))
                    throw new TlsException(AlertDescription.BadRecordMac, "SM4 AEAD authentication tag mismatch");
            }
            catch (CryptographicException e)
            { throw new TlsException(AlertDescription.BadRecordMac, e.Message); }
            return;
        }
        if (_aegis != null)
        {
            byte[] nonce = BuildNonce();
            _seqNum++;
            if (!_aegis.TryDecryptInto(nonce, encrypted, plaintext, aad))
                throw new TlsException(AlertDescription.BadRecordMac, "AEGIS authentication tag mismatch");
            return;
        }

        Span<byte> nonceSpan = stackalloc byte[_iv.Length];
        BuildNonceInto(nonceSpan);
        _seqNum++;

        if (_alg == AeadAlgorithm.ChaCha20Poly1305)
            _chachaManaged!.Decrypt(nonceSpan, encrypted, plaintext, aad);
        else
            _aesManaged!.Decrypt(nonceSpan, encrypted, plaintext, aad);
    }

    /// <summary>Try to decrypt; returns false (without advancing seqNum) on authentication failure.</summary>
    public bool TryDecrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0) { plaintext = null; return false; }
        byte[] buf = new byte[ctLen];
        if (TryDecryptInto(encrypted, aad, buf))
        {
            plaintext = buf;
            return true;
        }
        plaintext = null;
        return false;
    }

    /// <summary>Try to decrypt into a caller-provided buffer. Returns false (without advancing
    /// seqNum) on authentication failure — RFC 8446 §5.5 trial-decryption semantics.</summary>
    [System.Runtime.CompilerServices.SkipLocalsInit]
    public bool TryDecryptInto(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, Span<byte> plaintext)
    {
        EnforceHardLimit();
        if (_useTlsTree) EnsureGostRecordKey();
        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0 || plaintext.Length != ctLen) return false;

        if (_mgm != null)
        {
            byte[] nonce = BuildNonce();
            if (_mgm.TryDecryptInto(nonce, encrypted, plaintext, aad)) { _seqNum++; return true; }
            return false;
        }
        if (_sm4 != null)
        {
            byte[] nonce = BuildNonce();
            if (_sm4.TryDecryptInto(nonce, encrypted, plaintext, aad)) { _seqNum++; return true; }
            return false;
        }
        if (_aegis != null)
        {
            byte[] nonce = BuildNonce();
            if (_aegis.TryDecryptInto(nonce, encrypted, plaintext, aad)) { _seqNum++; return true; }
            return false;
        }

        Span<byte> nonceSpan = stackalloc byte[_iv.Length];
        BuildNonceInto(nonceSpan);

        try
        {
            if (_alg == AeadAlgorithm.ChaCha20Poly1305)
                _chachaManaged!.Decrypt(nonceSpan, encrypted, plaintext, aad);
            else
                _aesManaged!.Decrypt(nonceSpan, encrypted, plaintext, aad);
            _seqNum++;
            return true;
        }
        catch (CryptographicException)
        {
            // AuthenticationTagMismatchException derives from CryptographicException, so
            // this single catch covers both the BCL and managed-fallback failure paths.
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
            AeadAlgorithm.MgmKuznyechik or AeadAlgorithm.MgmMagma => _gostSnmax,
            AeadAlgorithm.Sm4Gcm or AeadAlgorithm.Sm4Ccm          => Sm4HardLimit,
            AeadAlgorithm.Aegis128L or AeadAlgorithm.Aegis256     => AegisHardLimit,
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
        _aegis?.Dispose();
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_iv);
    }
}
