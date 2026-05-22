namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// SM3 (GB/T 32905-2016) hash + HMAC for the RFC 8998 key schedule. BCL has no SM3, so the SM4
/// suites use the sentinel <see cref="Sm3Name"/> and Hkdf/KeySchedule/TranscriptHash dispatch here
/// (same pattern as <see cref="GostKdf"/>).
/// </summary>
internal static class Sm3Kdf
{
    public static readonly HashAlgorithmName Sm3Name = new("SM3");
    private const int BlockSize = 64; // SM3 HMAC block size (bytes)

    public static bool IsSm3(HashAlgorithmName hash) => hash.Name == "SM3";

    public static byte[] Hash(byte[] data) => ChineseCrypto.SM3.ComputeHash(data);

    /// <summary>HMAC-SM3 (RFC 2104 construction over GB/T 32905-2016).</summary>
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
