namespace TLS;

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// AES-GCM AEAD wrapper backed by BouncyCastle's <see cref="AesEngine"/> + <see cref="GcmBlockCipher"/>.
/// API mirrors <see cref="System.Security.Cryptography.AesGcm"/> (constructor + span-based
/// Encrypt/Decrypt) so call-site swaps are one-line.
///
/// Internally we cache a single <see cref="GcmBlockCipher"/> per instance and re-Init it on
/// every call rather than constructing a fresh one — BC's Init() resets all per-message
/// state (counters, hash sub-key powers, etc.) cleanly, and recycling the cipher avoids ~8
/// per-call buffer allocations that dominated bulk-transfer GC pressure.
///
/// BC's AesEngine uses <see cref="System.Runtime.Intrinsics.X86.Aes"/> (AES-NI hardware) when
/// the host CPU exposes it; this swap removes the BCrypt/OpenSSL P/Invoke path while keeping
/// hardware-accelerated AES.
/// </summary>
internal sealed class AesGcmManaged : IDisposable
{
    private readonly byte[] _key;
    private readonly int _tagLen;
    private readonly GcmBlockCipher _cipher;
    private readonly KeyParameter _keyParam;
    private bool _disposed;

    public AesGcmManaged(ReadOnlySpan<byte> key, int tagSizeBytes)
    {
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            throw new ArgumentException("AES key must be 128, 192, or 256 bits", nameof(key));
        if (tagSizeBytes != 12 && tagSizeBytes != 13 && tagSizeBytes != 14 && tagSizeBytes != 15 && tagSizeBytes != 16)
            throw new ArgumentException("AES-GCM tag must be 12-16 bytes", nameof(tagSizeBytes));
        _key = key.ToArray();
        _tagLen = tagSizeBytes;
        _cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
        _keyParam = new KeyParameter(_key);
    }

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> into <paramref name="output"/> as ciphertext||tag
    /// (BC's natural GCM output layout). <c>output.Length</c> MUST equal
    /// <c>plaintext.Length + tagSizeBytes</c>. Caller is responsible for slicing if needed.
    ///
    /// Removes the previous ~plaintext.Length scratch buffer (was ~16 KB per record on the
    /// 16 KB plaintext path) — BC now writes directly into the caller's span.
    /// </summary>
    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        Span<byte> output, ReadOnlySpan<byte> aad = default)
    {
        EnsureNotDisposed();
        if (output.Length != plaintext.Length + _tagLen)
            throw new ArgumentException($"output must be plaintext.Length + {_tagLen} bytes (got {output.Length})");

        // BC's AeadParameters wants byte[]; nonce (12 B) and aad (5 B for TLS) are tiny —
        // not worth pooling at this size.
        _cipher.Init(true, new AeadParameters(_keyParam, _tagLen * 8, nonce.ToArray(), aad.ToArray()));

        // BC GCM writes ciphertext || tag in one contiguous run. Feed plaintext via the span
        // overload, then DoFinal flushes any buffered block + appends the tag.
        int off = _cipher.ProcessBytes(plaintext, output);
        off += _cipher.DoFinal(output.Slice(off));
        // Sanity: BC's GetOutputSize for AEAD-encrypt returns plaintext.Length + tagLen.
        // If those don't match, our caller's slice is wrong (or BC changed semantics).
    }

    /// <summary>
    /// Decrypt <paramref name="ctAndTag"/> (ciphertext||tag concatenated) into
    /// <paramref name="plaintext"/>. <c>plaintext.Length</c> MUST equal
    /// <c>ctAndTag.Length - tagSizeBytes</c>. Throws <see cref="AuthenticationTagMismatchException"/>
    /// on tag failure.
    /// </summary>
    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ctAndTag,
        Span<byte> plaintext, ReadOnlySpan<byte> aad = default)
    {
        EnsureNotDisposed();
        if (ctAndTag.Length < _tagLen || plaintext.Length != ctAndTag.Length - _tagLen)
            throw new ArgumentException($"plaintext.Length must equal ctAndTag.Length - {_tagLen}");

        _cipher.Init(false, new AeadParameters(_keyParam, _tagLen * 8, nonce.ToArray(), aad.ToArray()));

        // Feed ciphertext+tag as one span — BC GCM internally separates them at DoFinal.
        int off = _cipher.ProcessBytes(ctAndTag, plaintext);
        try
        {
            _cipher.DoFinal(plaintext.Slice(off));
        }
        catch (InvalidCipherTextException)
        {
            // Wipe any partial plaintext before throwing — BC may have written some bytes
            // before the tag check failed.
            CryptographicOperations.ZeroMemory(plaintext);
            throw new AuthenticationTagMismatchException();
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AesGcmManaged));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
    }
}
