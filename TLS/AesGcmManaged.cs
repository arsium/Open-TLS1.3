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

    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad = default)
    {
        EnsureNotDisposed();
        if (ciphertext.Length != plaintext.Length) throw new ArgumentException("ciphertext length must equal plaintext length");
        if (tag.Length != _tagLen) throw new ArgumentException($"tag must be {_tagLen} bytes");

        // BC's AeadParameters wants byte[]; we have to copy the nonce/AAD once per call.
        // These are small (12 + ~13 bytes for TLS records) compared to the per-call cipher
        // construction we used to do.
        _cipher.Init(true, new AeadParameters(_keyParam, _tagLen * 8, nonce.ToArray(), aad.ToArray()));

        // BC GCM produces ciphertext || tag in one output buffer; split into caller's spans.
        int outLen = _cipher.GetOutputSize(plaintext.Length);
        byte[] outBuf = new byte[outLen];
        // ProcessBytes has a span overload — feed the plaintext directly without ToArray().
        int off = _cipher.ProcessBytes(plaintext, outBuf);
        off += _cipher.DoFinal(outBuf.AsSpan(off));

        new ReadOnlySpan<byte>(outBuf, 0, plaintext.Length).CopyTo(ciphertext);
        new ReadOnlySpan<byte>(outBuf, plaintext.Length, _tagLen).CopyTo(tag);
        CryptographicOperations.ZeroMemory(outBuf);
    }

    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad = default)
    {
        EnsureNotDisposed();
        if (plaintext.Length != ciphertext.Length) throw new ArgumentException("plaintext length must equal ciphertext length");
        if (tag.Length != _tagLen) throw new ArgumentException($"tag must be {_tagLen} bytes");

        _cipher.Init(false, new AeadParameters(_keyParam, _tagLen * 8, nonce.ToArray(), aad.ToArray()));

        int outLen = _cipher.GetOutputSize(ciphertext.Length + _tagLen);
        byte[] outBuf = new byte[outLen];
        // Feed ciphertext then tag — Span overloads avoid the inBuf concatenation copy.
        int off = _cipher.ProcessBytes(ciphertext, outBuf);
        off += _cipher.ProcessBytes(tag, outBuf.AsSpan(off));
        try
        {
            off += _cipher.DoFinal(outBuf.AsSpan(off));
        }
        catch (InvalidCipherTextException)
        {
            CryptographicOperations.ZeroMemory(outBuf);
            throw new AuthenticationTagMismatchException();
        }

        new ReadOnlySpan<byte>(outBuf, 0, plaintext.Length).CopyTo(plaintext);
        CryptographicOperations.ZeroMemory(outBuf);
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
