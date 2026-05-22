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

    public static byte[] Hash(byte[] data)
    {
        using var h = Streebog256.Create();
        return h.ComputeHash(data);
    }

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
}
