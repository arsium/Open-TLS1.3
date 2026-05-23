namespace TLS;

using System.Security.Cryptography;
using OpenGost.Security.Cryptography;

/// <summary>
/// GOST cryptographic algorithms for TLS integration. Thin facade over the vendored
/// OpenGost managed implementations (GOST R 34.12-2015 Kuznyechik/Magma, GOST R 34.11-2012
/// Streebog, CMAC/OMAC). Signatures (GOST R 34.10-2012) are not yet wired in.
/// </summary>
public static class GostCrypto
{
    /// <summary>Kuznyechik (GOST R 34.12-2015 "Grasshopper") 128-bit block cipher.</summary>
    public static class Kuznyechik
    {
        public const int BlockSize = GrasshopperManaged.BlockSize;
        public const int KeySize = GrasshopperManaged.KeySize;

        public static byte[] EncryptBlock(byte[] key, byte[] plaintext) => Transform(key, plaintext, encrypt: true);
        public static byte[] DecryptBlock(byte[] key, byte[] ciphertext) => Transform(key, ciphertext, encrypt: false);

        private static byte[] Transform(byte[] key, byte[] block, bool encrypt)
        {
            if (key.Length != KeySize) throw new ArgumentException("Invalid key size", nameof(key));
            if (block.Length != BlockSize) throw new ArgumentException("Invalid block size", nameof(block));

            using var cipher = new GrasshopperManaged(key);
            byte[] output = new byte[BlockSize];
            if (encrypt) cipher.EncryptBlock(block, 0, output, 0);
            else         cipher.DecryptBlock(block, 0, output, 0);
            return output;
        }
    }

    /// <summary>Magma (GOST R 34.12-2015 / 28147-89) 64-bit block cipher.</summary>
    public static class Magma
    {
        public const int BlockSize = MagmaManaged.BlockSize;
        public const int KeySize = MagmaManaged.KeySize;

        public static byte[] EncryptBlock(byte[] key, byte[] plaintext) => Transform(key, plaintext, encrypt: true);
        public static byte[] DecryptBlock(byte[] key, byte[] ciphertext) => Transform(key, ciphertext, encrypt: false);

        private static byte[] Transform(byte[] key, byte[] block, bool encrypt)
        {
            if (key.Length != KeySize) throw new ArgumentException("Invalid key size", nameof(key));
            if (block.Length != BlockSize) throw new ArgumentException("Invalid block size", nameof(block));

            using var cipher = new MagmaManaged(key);
            byte[] output = new byte[BlockSize];
            if (encrypt) cipher.EncryptBlock(block, 0, output, 0);
            else         cipher.DecryptBlock(block, 0, output, 0);
            return output;
        }
    }

    /// <summary>GOST R 34.11-2012 (Streebog) hash function.</summary>
    public static class Streebog
    {
        public static byte[] Hash256(byte[] data) => Streebog256Managed.Hash(data);
        public static byte[] Hash512(byte[] data) => Streebog512Managed.Hash(data);
    }

    /// <summary>Check if a cipher suite is a GOST suite.</summary>
    public static bool IsGostCipherSuite(CipherSuite suite) =>
        suite is CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
              or CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
              or CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
              or CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S;
}
