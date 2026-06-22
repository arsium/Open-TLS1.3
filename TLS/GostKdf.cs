namespace TLS;

using System.Security.Cryptography;
using OpenGost.Security.Cryptography;

/// <summary>
/// Streebog-256 (GOST R 34.11-2012) hash + HMAC for the RFC 9367 GOST key schedule.
/// The TLS stack threads the chosen hash through <see cref="HashAlgorithmName"/>; BCL has no
/// Streebog, so GOST suites use the sentinel <see cref="Streebog256Name"/> and the few HMAC/hash
/// call sites dispatch here.
/// </summary>
internal static class GostKdf
{
    public static readonly HashAlgorithmName Streebog256Name = new("STREEBOG256");
    private const int BlockSize = 64; // Streebog-256 HMAC block size (bytes)

    public static bool IsStreebog(HashAlgorithmName hash) => hash.Name == "STREEBOG256";

    public static byte[] Hash(byte[] data) => Streebog256Managed.Hash(data);

    /// <summary>HMAC-Streebog256 (RFC 2104 construction over GOST R 34.11-2012-256).</summary>
    public static byte[] Hmac(byte[] key, byte[] data)
    {
        byte[] k = key;
        if (k.Length > BlockSize) k = Hash(k);
        if (k.Length < BlockSize)
        {
            byte[] padded = new byte[BlockSize];
            Buffer.BlockCopy(k, 0, padded, 0, k.Length);
            k = padded;
        }

        byte[] inner = new byte[BlockSize + data.Length];
        byte[] outer = new byte[BlockSize + 32];
        for (int i = 0; i < BlockSize; i++)
        {
            inner[i] = (byte)(k[i] ^ 0x36);
            outer[i] = (byte)(k[i] ^ 0x5c);
        }
        Buffer.BlockCopy(data, 0, inner, BlockSize, data.Length);

        byte[] innerHash = Hash(inner);
        Buffer.BlockCopy(innerHash, 0, outer, BlockSize, 32);
        return Hash(outer);
    }

    /// <summary>
    /// RFC 9367 §4.1.2 TLSTREE external re-keying:
    ///   TLSTREE(K, i) = KDF_3(KDF_2(KDF_1(K, STR_8(i &amp; C1)), STR_8(i &amp; C2)), STR_8(i &amp; C3)).
    /// C1/C2/C3 are the per-suite constants from Table 1. Returns the 32-byte per-record key.
    /// </summary>
    public static byte[] TlsTree(byte[] kRoot, ulong seqnum, ulong c1, ulong c2, ulong c3)
    {
        byte[] k1 = Kdf(kRoot, "level1", Str8(seqnum & c1));
        byte[] k2 = Kdf(k1, "level2", Str8(seqnum & c2));
        return Kdf(k2, "level3", Str8(seqnum & c3));
    }

    // RFC 7836 §4.5: KDF_GOSTR3411_2012_256(K, label, seed)
    //   = HMAC_GOSTR3411_2012_256(K, 0x01 | label | 0x00 | seed | 0x01 | 0x00).
    private static byte[] Kdf(byte[] key, string label, byte[] seed)
    {
        byte[] lbl = System.Text.Encoding.ASCII.GetBytes(label);
        byte[] msg = new byte[1 + lbl.Length + 1 + seed.Length + 2];
        int o = 0;
        msg[o++] = 0x01;
        Buffer.BlockCopy(lbl, 0, msg, o, lbl.Length); o += lbl.Length;
        msg[o++] = 0x00;
        Buffer.BlockCopy(seed, 0, msg, o, seed.Length); o += seed.Length;
        msg[o++] = 0x01; // [L]_b = 256 (big-endian 16-bit)
        msg[o] = 0x00;
        return Hmac(key, msg);
    }

    // STR_8: 8-byte big-endian representation of a 64-bit value (RFC 7836 / GOST convention).
    private static byte[] Str8(ulong v)
    {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[7 - i] = (byte)(v >> (8 * i));
        return b;
    }
}
