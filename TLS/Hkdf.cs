namespace TLS;

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>HKDF key derivation (RFC 5869) with TLS 1.3 label functions (RFC 8446 §7.1).</summary>
public static class Hkdf
{
    /// <summary>HKDF-Extract(salt, IKM) → PRK</summary>
    public static byte[] Extract(HashAlgorithmName hash, byte[]? salt, byte[] ikm)
    {
        if (salt == null || salt.Length == 0)
            salt = new byte[HashLen(hash)];

        if (GostKdf.IsStreebog(hash))
            return GostKdf.Hmac(salt, ikm);
        if (Sm3Kdf.IsSm3(hash))
            return Sm3Kdf.Hmac(salt, ikm);

        return HmacForHash(hash, salt, ikm);
    }

    private static byte[] HmacForHash(HashAlgorithmName hash, byte[] key, byte[] data)
    {
        if (hash == HashAlgorithmName.SHA256) return Sha2Managed.HmacSha256(key, data);
        if (hash == HashAlgorithmName.SHA384) return Sha2Managed.HmacSha384(key, data);
        if (hash == HashAlgorithmName.SHA512) return Sha2Managed.HmacSha512(key, data);
        throw new ArgumentException($"Unsupported HMAC hash: {hash}");
    }

    /// <summary>HKDF-Expand(PRK, info, L) → OKM</summary>
    public static byte[] Expand(HashAlgorithmName hash, byte[] prk, byte[] info, int length)
    {
        // Streebog and SM3 still go through their one-shot HMACs — those don't expose an
        // incremental API. SHA-2 uses BC's HMac with Init-once / Reset-per-round so we
        // allocate the HMac + KeyParameter exactly once instead of every round.
        if (GostKdf.IsStreebog(hash) || Sm3Kdf.IsSm3(hash))
            return ExpandOneShot(hash, prk, info, length);
        return ExpandSha2(hash, prk, info, length);
    }

    private static byte[] ExpandSha2(HashAlgorithmName hash, byte[] prk, byte[] info, int length)
    {
        int hashLen = HashLen(hash);
        int n = (length + hashLen - 1) / hashLen;
        byte[] result = new byte[length];
        byte[] block = new byte[hashLen];
        byte[] prev = Array.Empty<byte>();

        // One HMac + one KeyParameter allocated up front. Reset() rewinds to the keyed
        // inner state between rounds so subsequent BlockUpdate calls produce T(i) over
        // the same prk without redoing key padding.
        var hmac = new HMac(NewDigest(hash));
        hmac.Init(new KeyParameter(prk));
        Span<byte> counter = stackalloc byte[1];

        try
        {
            for (int i = 1; i <= n; i++)
            {
                hmac.Reset();
                if (prev.Length > 0) hmac.BlockUpdate(prev, 0, prev.Length);
                if (info.Length > 0) hmac.BlockUpdate(info, 0, info.Length);
                counter[0] = (byte)i;
                hmac.BlockUpdate(counter);
                hmac.DoFinal(block, 0);

                int off = (i - 1) * hashLen;
                Buffer.BlockCopy(block, 0, result, off, Math.Min(hashLen, length - off));

                // T(i-1) is key material; clear before swapping.
                if (prev.Length > 0)
                    CryptographicOperations.ZeroMemory(prev);
                // Hand the just-computed block to the next round; allocate a fresh
                // block buffer (we can't reuse the same byte[] because prev and block
                // would alias and the BlockUpdate on the next round would race the DoFinal).
                prev = block;
                block = new byte[hashLen];
            }
        }
        finally
        {
            if (prev.Length > 0)
                CryptographicOperations.ZeroMemory(prev);
            CryptographicOperations.ZeroMemory(block);
        }

        return result;
    }

    private static byte[] ExpandOneShot(HashAlgorithmName hash, byte[] prk, byte[] info, int length)
    {
        bool streebog = GostKdf.IsStreebog(hash);
        int hashLen = HashLen(hash);
        int n = (length + hashLen - 1) / hashLen;
        byte[] result = new byte[length];
        byte[] prev = Array.Empty<byte>();

        try
        {
            for (int i = 1; i <= n; i++)
            {
                byte[] msg = new byte[prev.Length + info.Length + 1];
                Buffer.BlockCopy(prev, 0, msg, 0, prev.Length);
                Buffer.BlockCopy(info, 0, msg, prev.Length, info.Length);
                msg[^1] = (byte)i;
                byte[] next = streebog ? GostKdf.Hmac(prk, msg) : Sm3Kdf.Hmac(prk, msg);
                CryptographicOperations.ZeroMemory(msg);

                if (prev.Length > 0) CryptographicOperations.ZeroMemory(prev);
                prev = next;

                int off = (i - 1) * hashLen;
                Buffer.BlockCopy(prev, 0, result, off, Math.Min(hashLen, length - off));
            }
        }
        finally
        {
            if (prev.Length > 0)
                CryptographicOperations.ZeroMemory(prev);
        }

        return result;
    }

    private static Org.BouncyCastle.Crypto.IDigest NewDigest(HashAlgorithmName hash)
    {
        if (hash == HashAlgorithmName.SHA256) return new Sha256Digest();
        if (hash == HashAlgorithmName.SHA384) return new Sha384Digest();
        if (hash == HashAlgorithmName.SHA512) return new Sha512Digest();
        throw new ArgumentException($"Unsupported hash: {hash}");
    }

    /// <summary>
    /// HKDF-Expand-Label(Secret, Label, Context, Length)
    /// = HKDF-Expand(Secret, HkdfLabel, Length)
    /// where HkdfLabel = uint16(Length) ‖ "tls13 "+Label (with length prefix) ‖ Context (with length prefix)
    /// </summary>
    public static byte[] ExpandLabel(HashAlgorithmName hash, byte[] secret,
        string label, byte[] context, int length)
    {
        byte[] fullLabel = System.Text.Encoding.ASCII.GetBytes("tls13 " + label);

        using var ms = new MemoryStream();
        BinaryHelper.WriteUInt16(ms, (ushort)length);
        ms.WriteByte((byte)fullLabel.Length);
        ms.Write(fullLabel);
        ms.WriteByte((byte)context.Length);
        ms.Write(context);

        return Expand(hash, secret, ms.ToArray(), length);
    }

    /// <summary>
    /// Derive-Secret(Secret, Label, Messages)
    /// = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    /// </summary>
    public static byte[] DeriveSecret(HashAlgorithmName hash, byte[] secret,
        string label, byte[] transcriptHash)
    {
        return ExpandLabel(hash, secret, label, transcriptHash, HashLen(hash));
    }

    public static int HashLen(HashAlgorithmName hash)
    {
        if (hash == HashAlgorithmName.SHA256) return 32;
        if (hash == HashAlgorithmName.SHA384) return 48;
        if (GostKdf.IsStreebog(hash)) return 32;
        if (Sm3Kdf.IsSm3(hash)) return 32;
        throw new ArgumentException($"Unsupported hash algorithm: {hash}");
    }
}
