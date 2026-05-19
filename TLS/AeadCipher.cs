namespace TLS;

using System.Security.Cryptography;

/// <summary>AEAD cipher with per-record nonce management for TLS 1.3. Supports AES-GCM and ChaCha20-Poly1305.</summary>
public sealed class AeadCipher : IDisposable
{
    private readonly byte[] _key;
    private readonly byte[] _iv; // 12 bytes
    private readonly bool _isChaCha20;
    private ulong _seqNum;

    public AeadCipher(byte[] key, byte[] iv, bool isChaCha20 = false)
    {
        _key = (byte[])key.Clone();
        _iv = (byte[])iv.Clone();
        _isChaCha20 = isChaCha20;
        _seqNum = 0;
    }

    /// <summary>Encrypt plaintext with AEAD. Returns ciphertext ‖ tag (16 bytes).</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        byte[] nonce = BuildNonce();
        _seqNum++;

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TlsConst.AeadTagLength];

        if (_isChaCha20)
        {
            using var chacha = new ChaCha20Poly1305(_key);
            chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        else
        {
            using var aes = new AesGcm(_key, TlsConst.AeadTagLength);
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

        int ctLen = encrypted.Length - TlsConst.AeadTagLength;
        if (ctLen < 0)
            throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");

        var ciphertext = encrypted[..ctLen];
        var tag = encrypted[ctLen..];
        byte[] plaintext = new byte[ctLen];

        if (_isChaCha20)
        {
            using var chacha = new ChaCha20Poly1305(_key);
            chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        else
        {
            using var aes = new AesGcm(_key, TlsConst.AeadTagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }

        return plaintext;
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
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_iv);
    }
}
