namespace TLS;

using System.Security.Cryptography;

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

        using var hmac = IncrementalHash.CreateHMAC(hash, salt);
        hmac.AppendData(ikm);
        return hmac.GetHashAndReset();
    }

    /// <summary>HKDF-Expand(PRK, info, L) → OKM</summary>
    public static byte[] Expand(HashAlgorithmName hash, byte[] prk, byte[] info, int length)
    {
        int hashLen = HashLen(hash);
        int n = (length + hashLen - 1) / hashLen;
        byte[] result = new byte[length];
        byte[] prev = Array.Empty<byte>();

        bool streebog = GostKdf.IsStreebog(hash);
        bool sm3 = Sm3Kdf.IsSm3(hash);
        for (int i = 1; i <= n; i++)
        {
            if (streebog || sm3)
            {
                byte[] msg = new byte[prev.Length + info.Length + 1];
                Buffer.BlockCopy(prev, 0, msg, 0, prev.Length);
                Buffer.BlockCopy(info, 0, msg, prev.Length, info.Length);
                msg[^1] = (byte)i;
                prev = streebog ? GostKdf.Hmac(prk, msg) : Sm3Kdf.Hmac(prk, msg);
            }
            else
            {
                using var hmac = IncrementalHash.CreateHMAC(hash, prk);
                hmac.AppendData(prev);
                hmac.AppendData(info);
                hmac.AppendData(new[] { (byte)i });
                prev = hmac.GetHashAndReset();
            }

            int off = (i - 1) * hashLen;
            Buffer.BlockCopy(prev, 0, result, off, Math.Min(hashLen, length - off));
        }

        return result;
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
