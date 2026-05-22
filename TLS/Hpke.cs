namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// HPKE (Hybrid Public Key Encryption) implementation per RFC 9180.
/// Supports DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
/// </summary>
public static class Hpke
{
    // RFC 9180 Algorithm Identifiers
    public const ushort KEM_DHKEM_X25519_HKDF_SHA256 = 0x0020;
    public const ushort KDF_HKDF_SHA256 = 0x0001;
    public const ushort AEAD_AES_128_GCM = 0x0001;

    // Algorithm parameters
    private const int Nk = 16;  // AES-128 key size
    private const int Nn = 12;  // AES-GCM nonce size
    private const int Nh = 32;  // SHA-256 hash size
    private const int Nsecret = 32; // X25519 shared secret size
    private const int Nenc = 32;   // X25519 encoded public key size

    // HPKE labels for HKDF-Expand-Label
    private const string HPKE_V1_LABEL = "HPKE-v1";

    /// <summary>HPKE encryption context for Seal/Open operations.</summary>
    public sealed class HpkeContext : IDisposable
    {
        private readonly byte[] _key;
        private readonly byte[] _baseNonce;
        private ulong _sequenceNumber;
        private readonly object _lock = new();

        internal HpkeContext(byte[] key, byte[] baseNonce)
        {
            _key = key;
            _baseNonce = baseNonce;
            _sequenceNumber = 0;
        }

        /// <summary>Seal (encrypt) plaintext with associated data.</summary>
        public byte[] Seal(byte[] aad, byte[] plaintext)
        {
            lock (_lock)
            {
                byte[] nonce = ComputeNonce(_sequenceNumber++);

                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16];

                using var aes = new AesGcm(_key, 16);
                aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

                // Return ciphertext || tag
                byte[] result = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
                return result;
            }
        }

        /// <summary>Open (decrypt) ciphertext with associated data.</summary>
        public byte[]? Open(byte[] aad, byte[] ciphertext)
        {
            if (ciphertext.Length < 16) return null; // Too short for tag

            lock (_lock)
            {
                byte[] nonce = ComputeNonce(_sequenceNumber++);

                // Split ciphertext and tag
                int plaintextLen = ciphertext.Length - 16;
                byte[] ct = ciphertext[..plaintextLen];
                byte[] tag = ciphertext[plaintextLen..];
                byte[] plaintext = new byte[plaintextLen];

                try
                {
                    using var aes = new AesGcm(_key, 16);
                    aes.Decrypt(nonce, ct, tag, plaintext, aad);
                    return plaintext;
                }
                catch (CryptographicException)
                {
                    return null; // Authentication failed
                }
            }
        }

        private byte[] ComputeNonce(ulong seq)
        {
            // nonce = base_nonce XOR seq (padded to nonce length)
            byte[] nonce = new byte[Nn];
            Buffer.BlockCopy(_baseNonce, 0, nonce, 0, Nn);

            // XOR with sequence number (big-endian)
            for (int i = 0; i < 8; i++)
            {
                byte seqByte = (byte)(seq >> (8 * (7 - i)));
                nonce[Nn - 8 + i] ^= seqByte;
            }
            return nonce;
        }

        public void Dispose()
        {
            Array.Clear(_key);
            Array.Clear(_baseNonce);
        }
    }

    /// <summary>DHKEM(X25519, HKDF-SHA256) Key Encapsulation Mechanism.</summary>
    public static class DhKem
    {
        /// <summary>Generate ephemeral keypair and shared secret with recipient public key.</summary>
        public static (byte[] enc, byte[] sharedSecret) Encap(byte[] pkR)
        {
            if (pkR.Length != 32) throw new ArgumentException("Invalid X25519 public key length");

            // Generate ephemeral keypair
            byte[] skE = X25519.GeneratePrivateKey();
            byte[] pkE = X25519.PublicFromPrivate(skE);

            // Compute shared secret
            byte[] dh = X25519.SharedSecret(skE, pkR);

            // Extract and expand shared secret (RFC 9180 §4.1)
            byte[] kemContext = CombineBytes(pkE, pkR);
            byte[] sharedSecret = ExtractAndExpand(dh, kemContext);

            Array.Clear(skE); // Clear ephemeral private key
            return (pkE, sharedSecret);
        }

        /// <summary>Recover shared secret using recipient private key and encapsulated key.</summary>
        public static byte[] Decap(byte[] enc, byte[] skR)
        {
            if (enc.Length != 32) throw new ArgumentException("Invalid encapsulated key length");
            if (skR.Length != 32) throw new ArgumentException("Invalid X25519 private key length");

            // Compute shared secret
            byte[] dh = X25519.SharedSecret(skR, enc);

            // Reconstruct KEM context
            byte[] pkR = X25519.PublicFromPrivate(skR);
            byte[] kemContext = CombineBytes(enc, pkR);

            return ExtractAndExpand(dh, kemContext);
        }

        private static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
        {
            // RFC 9180 §4.1: ExtractAndExpand for DHKEM
            string suiteId = "KEM" + ((char)0) + ((char)0) + ((char)(KEM_DHKEM_X25519_HKDF_SHA256 >> 8)) + ((char)(KEM_DHKEM_X25519_HKDF_SHA256 & 0xFF));
            byte[] suiteIdBytes = System.Text.Encoding.UTF8.GetBytes(suiteId);

            // Extract
            byte[] salt = LabeledExtract(Array.Empty<byte>(), "eae_prk", dh, suiteIdBytes);

            // Expand
            byte[] info = LabeledInfo("shared_secret", kemContext, Nsecret, suiteIdBytes);
            return Hkdf.Expand(HashAlgorithmName.SHA256, salt, info, Nsecret);
        }
    }

    /// <summary>HPKE Key Schedule for deriving encryption keys.</summary>
    public static class KeySchedule
    {
        /// <summary>Setup sender context (mode_base = 0x00).</summary>
        public static (byte[] enc, HpkeContext context) SetupBaseSender(byte[] pkR, byte[] info)
        {
            var (enc, sharedSecret) = DhKem.Encap(pkR);
            var context = KeyScheduleS(0x00, sharedSecret, info);
            Array.Clear(sharedSecret);
            return (enc, context);
        }

        /// <summary>Setup receiver context (mode_base = 0x00).</summary>
        public static HpkeContext SetupBaseReceiver(byte[] enc, byte[] skR, byte[] info)
        {
            byte[] sharedSecret = DhKem.Decap(enc, skR);
            var context = KeyScheduleR(0x00, sharedSecret, info);
            Array.Clear(sharedSecret);
            return context;
        }

        private static HpkeContext KeyScheduleS(byte mode, byte[] sharedSecret, byte[] info)
        {
            return KeyScheduleBase(mode, sharedSecret, info, Array.Empty<byte>(), Array.Empty<byte>());
        }

        private static HpkeContext KeyScheduleR(byte mode, byte[] sharedSecret, byte[] info)
        {
            return KeyScheduleBase(mode, sharedSecret, info, Array.Empty<byte>(), Array.Empty<byte>());
        }

        private static HpkeContext KeyScheduleBase(byte mode, byte[] sharedSecret, byte[] info, byte[] psk, byte[] pskId)
        {
            // RFC 9180 §5.1: Key Schedule
            string suiteId = BuildSuiteId();
            byte[] suiteIdBytes = System.Text.Encoding.UTF8.GetBytes(suiteId);

            // Verify PSK inputs
            if ((psk.Length == 0) != (pskId.Length == 0))
                throw new ArgumentException("PSK and PSK ID must both be empty or both non-empty");

            // Extract and expand
            byte[] pskIdHash = LabeledExtract(Array.Empty<byte>(), "psk_id_hash", pskId, suiteIdBytes);
            byte[] infoHash = LabeledExtract(Array.Empty<byte>(), "info_hash", info, suiteIdBytes);
            byte[] keyScheduleContext = CombineBytes(new[] { mode }, pskIdHash, infoHash);

            byte[] secret = LabeledExtract(sharedSecret, "secret", psk, suiteIdBytes);

            byte[] key = LabeledExpand(secret, "key", keyScheduleContext, Nk, suiteIdBytes);
            byte[] baseNonce = LabeledExpand(secret, "base_nonce", keyScheduleContext, Nn, suiteIdBytes);

            Array.Clear(secret);
            return new HpkeContext(key, baseNonce);
        }

        private static string BuildSuiteId()
        {
            return "HPKE" +
                   ((char)(KEM_DHKEM_X25519_HKDF_SHA256 >> 8)) + ((char)(KEM_DHKEM_X25519_HKDF_SHA256 & 0xFF)) +
                   ((char)(KDF_HKDF_SHA256 >> 8)) + ((char)(KDF_HKDF_SHA256 & 0xFF)) +
                   ((char)(AEAD_AES_128_GCM >> 8)) + ((char)(AEAD_AES_128_GCM & 0xFF));
        }
    }

    // HKDF-Expand-Label utilities for HPKE
    private static byte[] LabeledExtract(byte[] salt, string label, byte[] ikm, byte[] suiteId)
    {
        byte[] labeledIkm = CombineBytes(HPKE_V1_LABEL.ToUtf8(), suiteId, label.ToUtf8(), ikm);
        return Hkdf.Extract(HashAlgorithmName.SHA256, labeledIkm, salt);
    }

    private static byte[] LabeledExpand(byte[] prk, string label, byte[] info, int length, byte[] suiteId)
    {
        byte[] labeledInfo = LabeledInfo(label, info, length, suiteId);
        return Hkdf.Expand(HashAlgorithmName.SHA256, prk, labeledInfo, length);
    }

    private static byte[] LabeledInfo(string label, byte[] info, int length, byte[] suiteId)
    {
        using var ms = new MemoryStream();
        BinaryHelper.WriteUInt16(ms, (ushort)length);

        byte[] labeledInfoPrefix = CombineBytes(HPKE_V1_LABEL.ToUtf8(), suiteId, label.ToUtf8());
        BinaryHelper.WriteUInt16(ms, (ushort)labeledInfoPrefix.Length);
        ms.Write(labeledInfoPrefix);

        BinaryHelper.WriteUInt16(ms, (ushort)info.Length);
        ms.Write(info);

        return ms.ToArray();
    }

    private static byte[] CombineBytes(params byte[][] arrays)
    {
        int totalLength = arrays.Sum(a => a.Length);
        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }
}

// Extension method for string to UTF-8 conversion
internal static class StringExtensions
{
    public static byte[] ToUtf8(this string str) => System.Text.Encoding.UTF8.GetBytes(str);
}