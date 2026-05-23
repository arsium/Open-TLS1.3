namespace TLS;

using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

/// <summary>
/// RFC 8439 §2.8 AEAD_CHACHA20_POLY1305, pure managed.
///
/// Used as a portable replacement for <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>
/// on platforms whose underlying crypto provider lacks the cipher (notably Windows 7/8 builds,
/// and Windows 10 LTSC builds where BCrypt is missing CHACHA20_POLY1305).
///
/// API mirrors the BCL class: 32-byte key, 12-byte nonce, 16-byte tag.
/// </summary>
internal sealed class ChaCha20Poly1305Managed : IDisposable
{
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    private readonly byte[] _key;
    private bool _disposed;

    public ChaCha20Poly1305Managed(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize) throw new ArgumentException("Key must be 32 bytes", nameof(key));
        _key = key.ToArray();
    }

    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad)
    {
        EnsureNotDisposed();
        if (nonce.Length != NonceSize) throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));
        if (tag.Length != TagSize) throw new ArgumentException("Tag must be 16 bytes", nameof(tag));
        if (ciphertext.Length != plaintext.Length) throw new ArgumentException("Ciphertext length must equal plaintext length");

        // RFC 8439 §2.6: Poly1305 one-time key = first 32 bytes of ChaCha20 keystream at counter 0.
        Span<byte> polyKey = stackalloc byte[32];
        ChaCha20.Keystream(_key, nonce, 0, polyKey);

        // RFC 8439 §2.8.1: encrypt with ChaCha20 starting at counter 1.
        ChaCha20.XorKeystream(_key, nonce, 1, plaintext, ciphertext);

        ComputeAeadTag(polyKey, aad, ciphertext, tag);
        CryptographicOperations.ZeroMemory(polyKey);
    }

    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        EnsureNotDisposed();
        if (nonce.Length != NonceSize) throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));
        if (tag.Length != TagSize) throw new ArgumentException("Tag must be 16 bytes", nameof(tag));
        if (plaintext.Length != ciphertext.Length) throw new ArgumentException("Plaintext length must equal ciphertext length");

        // Recompute the expected tag from AAD || ciphertext and verify in constant time.
        Span<byte> polyKey = stackalloc byte[32];
        ChaCha20.Keystream(_key, nonce, 0, polyKey);

        Span<byte> expectedTag = stackalloc byte[TagSize];
        ComputeAeadTag(polyKey, aad, ciphertext, expectedTag);
        CryptographicOperations.ZeroMemory(polyKey);

        if (!CryptographicOperations.FixedTimeEquals(expectedTag, tag))
        {
            CryptographicOperations.ZeroMemory(expectedTag);
            // Match the BCL ChaCha20Poly1305 behaviour: throw on tag mismatch.
            throw new AuthenticationTagMismatchException();
        }
        CryptographicOperations.ZeroMemory(expectedTag);

        // Tag valid — decrypt with ChaCha20 starting at counter 1.
        ChaCha20.XorKeystream(_key, nonce, 1, ciphertext, plaintext);
    }

    // RFC 8439 §2.8: Poly1305 input is aad || pad16(aad) || ct || pad16(ct) || len(aad) || len(ct).
    private static void ComputeAeadTag(ReadOnlySpan<byte> polyKey, ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext, Span<byte> tag)
    {
        int aadPad = (16 - (aad.Length & 15)) & 15;
        int ctPad  = (16 - (ciphertext.Length & 15)) & 15;
        int totalLen = aad.Length + aadPad + ciphertext.Length + ctPad + 16;

        // Always rent from ArrayPool<byte>.Shared rather than new-allocating. For the typical
        // 16 KB TLS record this saves ~16 KB of GC pressure per Encrypt / Decrypt; for the
        // small-input case the pool's minimum bucket is essentially free.
        byte[] rented = ArrayPool<byte>.Shared.Rent(totalLen);
        Span<byte> buf = new Span<byte>(rented, 0, totalLen);
        buf.Clear();
        try
        {
            int off = 0;
            aad.CopyTo(buf.Slice(off, aad.Length)); off += aad.Length;
            off += aadPad; // pad bytes already zero
            ciphertext.CopyTo(buf.Slice(off, ciphertext.Length)); off += ciphertext.Length;
            off += ctPad;
            BinaryPrimitives.WriteUInt64LittleEndian(buf.Slice(off, 8), (ulong)aad.Length); off += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(buf.Slice(off, 8), (ulong)ciphertext.Length);

            Poly1305.ComputeTag(polyKey, buf, tag);
        }
        finally
        {
            // Wipe the rented buffer (it carries the ciphertext we just authenticated)
            // before handing it back to the pool — defence against later renters reading it.
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, totalLen));
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ChaCha20Poly1305Managed));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
    }
}
