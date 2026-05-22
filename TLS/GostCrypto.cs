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
        public const int BlockSize = 16; // 128 bits
        public const int KeySize = 32;   // 256 bits

        public static byte[] EncryptBlock(byte[] key, byte[] plaintext) => Transform(key, plaintext, encrypt: true);
        public static byte[] DecryptBlock(byte[] key, byte[] ciphertext) => Transform(key, ciphertext, encrypt: false);

        private static byte[] Transform(byte[] key, byte[] block, bool encrypt)
        {
            if (key.Length != KeySize) throw new ArgumentException("Invalid key size", nameof(key));
            if (block.Length != BlockSize) throw new ArgumentException("Invalid block size", nameof(block));

            using var alg = new GrasshopperManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };
            using var t = encrypt ? alg.CreateEncryptor(key, null) : alg.CreateDecryptor(key, null);
            return t.TransformFinalBlock(block, 0, block.Length);
        }
    }

    /// <summary>Magma (GOST R 34.12-2015 / 28147-89) 64-bit block cipher.</summary>
    public static class Magma
    {
        public const int BlockSize = 8;  // 64 bits
        public const int KeySize = 32;   // 256 bits

        public static byte[] EncryptBlock(byte[] key, byte[] plaintext) => Transform(key, plaintext, encrypt: true);
        public static byte[] DecryptBlock(byte[] key, byte[] ciphertext) => Transform(key, ciphertext, encrypt: false);

        private static byte[] Transform(byte[] key, byte[] block, bool encrypt)
        {
            if (key.Length != KeySize) throw new ArgumentException("Invalid key size", nameof(key));
            if (block.Length != BlockSize) throw new ArgumentException("Invalid block size", nameof(block));

            using var alg = new MagmaManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };
            using var t = encrypt ? alg.CreateEncryptor(key, null) : alg.CreateDecryptor(key, null);
            return t.TransformFinalBlock(block, 0, block.Length);
        }
    }

    /// <summary>GOST R 34.11-2012 (Streebog) hash function.</summary>
    public static class Streebog
    {
        public static byte[] Hash256(byte[] data)
        {
            using var h = Streebog256.Create();
            return h.ComputeHash(data);
        }

        public static byte[] Hash512(byte[] data)
        {
            using var h = Streebog512.Create();
            return h.ComputeHash(data);
        }
    }

    /// <summary>OMAC (CMAC over a GOST block cipher) per GOST R 34.13-2015. Not used by the
    /// RFC 9367 MGM suites, but exposed as a verified GOST primitive.</summary>
    public static class Omac
    {
        public static byte[] Kuznyechik(byte[] key, byte[] data)
        {
            using var mac = new CMACGrasshopper(key);
            return mac.ComputeHash(data);
        }

        public static byte[] Magma(byte[] key, byte[] data)
        {
            using var mac = new CMACMagma(key);
            return mac.ComputeHash(data);
        }
    }

    /// <summary>Check if a cipher suite is a GOST suite.</summary>
    public static bool IsGostCipherSuite(CipherSuite suite) =>
        suite is CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
              or CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
              or CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
              or CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S;
}
