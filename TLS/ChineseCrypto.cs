namespace TLS;

using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

/// <summary>
/// Chinese National Standard cryptographic algorithms based on RFC 8998.
/// SM4 (GB/T 32907-2016), SM3 (GB/T 32905-2016), and an SM2 framework.
/// </summary>
public static class ChineseCrypto
{
    /// <summary>SM4 block cipher (GB/T 32907-2016). 128-bit block, 128-bit key, big-endian words.</summary>
    public static class SM4
    {
        public const int BlockSize = 16; // 128 bits
        public const int KeySize = 16;   // 128 bits

        private static readonly byte[] SBOX =
        {
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        };

        private static readonly uint[] CK =
        {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };

        private static readonly uint[] FK = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

        private static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));

        private static uint Tau(uint a) =>
            ((uint)SBOX[a >> 24] << 24) | ((uint)SBOX[(a >> 16) & 0xff] << 16) |
            ((uint)SBOX[(a >> 8) & 0xff] << 8) | SBOX[a & 0xff];

        private static uint LKey(uint b) => b ^ Rotl(b, 13) ^ Rotl(b, 23);
        private static uint L(uint b) => b ^ Rotl(b, 2) ^ Rotl(b, 10) ^ Rotl(b, 18) ^ Rotl(b, 24);

        /// <summary>Expand a 128-bit key into the 32 encryption round keys.</summary>
        public static uint[] ExpandKey(byte[] key)
        {
            if (key.Length != KeySize) throw new ArgumentException("SM4 requires a 128-bit key", nameof(key));
            uint k0 = BinaryPrimitives.ReadUInt32BigEndian(key.AsSpan(0)) ^ FK[0];
            uint k1 = BinaryPrimitives.ReadUInt32BigEndian(key.AsSpan(4)) ^ FK[1];
            uint k2 = BinaryPrimitives.ReadUInt32BigEndian(key.AsSpan(8)) ^ FK[2];
            uint k3 = BinaryPrimitives.ReadUInt32BigEndian(key.AsSpan(12)) ^ FK[3];

            uint[] rk = new uint[32];
            rk[0] = k0 ^ LKey(Tau(k1 ^ k2 ^ k3 ^ CK[0]));
            rk[1] = k1 ^ LKey(Tau(k2 ^ k3 ^ rk[0] ^ CK[1]));
            rk[2] = k2 ^ LKey(Tau(k3 ^ rk[0] ^ rk[1] ^ CK[2]));
            rk[3] = k3 ^ LKey(Tau(rk[0] ^ rk[1] ^ rk[2] ^ CK[3]));
            for (int i = 4; i < 32; i++)
                rk[i] = rk[i - 4] ^ LKey(Tau(rk[i - 3] ^ rk[i - 2] ^ rk[i - 1] ^ CK[i]));
            return rk;
        }

        /// <summary>Encrypt one 16-byte block with precomputed round keys.</summary>
        public static void EncryptBlock(uint[] rk, ReadOnlySpan<byte> input, Span<byte> output)
        {
            uint x0 = BinaryPrimitives.ReadUInt32BigEndian(input);
            uint x1 = BinaryPrimitives.ReadUInt32BigEndian(input[4..]);
            uint x2 = BinaryPrimitives.ReadUInt32BigEndian(input[8..]);
            uint x3 = BinaryPrimitives.ReadUInt32BigEndian(input[12..]);

            for (int i = 0; i < 32; i += 4)
            {
                x0 ^= L(Tau(x1 ^ x2 ^ x3 ^ rk[i]));
                x1 ^= L(Tau(x2 ^ x3 ^ x0 ^ rk[i + 1]));
                x2 ^= L(Tau(x3 ^ x0 ^ x1 ^ rk[i + 2]));
                x3 ^= L(Tau(x0 ^ x1 ^ x2 ^ rk[i + 3]));
            }

            BinaryPrimitives.WriteUInt32BigEndian(output, x3);
            BinaryPrimitives.WriteUInt32BigEndian(output[4..], x2);
            BinaryPrimitives.WriteUInt32BigEndian(output[8..], x1);
            BinaryPrimitives.WriteUInt32BigEndian(output[12..], x0);
        }

        /// <summary>Encrypt a single block (convenience; expands the key each call).</summary>
        public static byte[] EncryptBlock(byte[] key, byte[] plaintext)
        {
            if (plaintext.Length != BlockSize) throw new ArgumentException("Invalid block size", nameof(plaintext));
            byte[] o = new byte[BlockSize];
            EncryptBlock(ExpandKey(key), plaintext, o);
            return o;
        }
    }

    /// <summary>SM3 hash function (GB/T 32905-2016). 256-bit output, 512-bit blocks.</summary>
    public static class SM3
    {
        public const int HashSize = 32; // 256 bits

        private static readonly uint[] IV =
        {
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        };

        private static uint Rotl(uint x, int n) => n % 32 == 0 ? x : (x << n) | (x >> (32 - n));
        private static uint P0(uint x) => x ^ Rotl(x, 9) ^ Rotl(x, 17);
        private static uint P1(uint x) => x ^ Rotl(x, 15) ^ Rotl(x, 23);
        private static uint FF(int j, uint x, uint y, uint z) => j < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);
        private static uint GG(int j, uint x, uint y, uint z) => j < 16 ? x ^ y ^ z : (x & y) | (~x & z);

        public static byte[] ComputeHash(byte[] data)
        {
            long bitLen = (long)data.Length * 8;
            int padLen = (56 - (data.Length + 1) % 64 + 64) % 64;
            byte[] msg = new byte[data.Length + 1 + padLen + 8];
            Buffer.BlockCopy(data, 0, msg, 0, data.Length);
            msg[data.Length] = 0x80;
            BinaryPrimitives.WriteUInt64BigEndian(msg.AsSpan(msg.Length - 8), (ulong)bitLen);

            uint[] v = (uint[])IV.Clone();
            uint[] w = new uint[68];
            uint[] w1 = new uint[64];

            for (int b = 0; b < msg.Length; b += 64)
            {
                for (int i = 0; i < 16; i++)
                    w[i] = BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(b + i * 4));
                for (int i = 16; i < 68; i++)
                    w[i] = P1(w[i - 16] ^ w[i - 9] ^ Rotl(w[i - 3], 15)) ^ Rotl(w[i - 13], 7) ^ w[i - 6];
                for (int i = 0; i < 64; i++)
                    w1[i] = w[i] ^ w[i + 4];

                uint a = v[0], bb = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h = v[7];
                for (int j = 0; j < 64; j++)
                {
                    uint tj = j < 16 ? 0x79CC4519u : 0x7A879D8Au;
                    uint ss1 = Rotl(Rotl(a, 12) + e + Rotl(tj, j % 32), 7);
                    uint ss2 = ss1 ^ Rotl(a, 12);
                    uint tt1 = FF(j, a, bb, c) + d + ss2 + w1[j];
                    uint tt2 = GG(j, e, f, g) + h + ss1 + w[j];
                    d = c; c = Rotl(bb, 9); bb = a; a = tt1;
                    h = g; g = Rotl(f, 19); f = e; e = P0(tt2);
                }
                v[0] ^= a; v[1] ^= bb; v[2] ^= c; v[3] ^= d;
                v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
            }

            byte[] result = new byte[HashSize];
            for (int i = 0; i < 8; i++)
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(i * 4), v[i]);
            return result;
        }
    }

    /// <summary>SM2 elliptic-curve signatures (GB/T 32918.2 / RFC 8998), over the SM3 hash.</summary>
    public static class SM2
    {
        /// <summary>SM2 prime-field short-Weierstrass curve parameters (y^2 = x^3 + ax + b mod p).</summary>
        public sealed class Curve
        {
            public readonly BigInteger P, A, B, N, Gx, Gy;
            public Curve(string p, string a, string b, string n, string gx, string gy)
            { P = U(p); A = U(a); B = U(b); N = U(n); Gx = U(gx); Gy = U(gy); }
            private static BigInteger U(string hex) =>
                new(Convert.FromHexString(hex), isUnsigned: true, isBigEndian: true);
        }

        /// <summary>The production sm2p256v1 / curveSM2 domain parameters.</summary>
        public static readonly Curve Sm2P256 = new(
            p:  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            a:  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            b:  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            n:  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            gx: "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            gy: "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");

        /// <summary>Default user identity per GB/T (used for certificate verification).</summary>
        public const string DefaultId = "1234567812345678";

        // ---- affine EC arithmetic over GF(p) ----
        private static (BigInteger x, BigInteger y)? Add(Curve c, (BigInteger x, BigInteger y)? p1, (BigInteger x, BigInteger y)? p2)
        {
            if (p1 is null) return p2;
            if (p2 is null) return p1;
            var (x1, y1) = p1.Value;
            var (x2, y2) = p2.Value;
            BigInteger lambda;
            if (x1 == x2)
            {
                if ((y1 + y2) % c.P == 0) return null; // P + (-P) = O
                lambda = (3 * x1 * x1 + c.A) * ModInv(2 * y1, c.P) % c.P;
            }
            else
            {
                lambda = Mod(y2 - y1, c.P) * ModInv(Mod(x2 - x1, c.P), c.P) % c.P;
            }
            lambda = Mod(lambda, c.P);
            var x3 = Mod(lambda * lambda - x1 - x2, c.P);
            var y3 = Mod(lambda * (x1 - x3) - y1, c.P);
            return (x3, y3);
        }

        private static (BigInteger x, BigInteger y)? Multiply(Curve c, BigInteger k, (BigInteger x, BigInteger y)? point)
        {
            (BigInteger x, BigInteger y)? result = null;
            var addend = point;
            while (k > 0)
            {
                if (!k.IsEven) result = Add(c, result, addend);
                addend = Add(c, addend, addend);
                k >>= 1;
            }
            return result;
        }

        private static BigInteger Mod(BigInteger a, BigInteger m) { var r = a % m; return r.Sign < 0 ? r + m : r; }
        private static BigInteger ModInv(BigInteger a, BigInteger m) => BigInteger.ModPow(Mod(a, m), m - 2, m);
        private static BigInteger FromBe(byte[] b) => new(b, isUnsigned: true, isBigEndian: true);

        private static byte[] ToBe(BigInteger v, int size)
        {
            byte[] full = v.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (full.Length == size) return full;
            byte[] r = new byte[size];
            Buffer.BlockCopy(full, Math.Max(0, full.Length - size), r, Math.Max(0, size - full.Length), Math.Min(size, full.Length));
            return r;
        }

        /// <summary>ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py).</summary>
        public static byte[] ComputeZ(Curve c, string id, BigInteger px, BigInteger py)
        {
            byte[] idBytes = System.Text.Encoding.ASCII.GetBytes(id);
            int entl = idBytes.Length * 8;
            using var ms = new MemoryStream();
            ms.WriteByte((byte)(entl >> 8));
            ms.WriteByte((byte)entl);
            ms.Write(idBytes);
            ms.Write(ToBe(c.A, 32)); ms.Write(ToBe(c.B, 32));
            ms.Write(ToBe(c.Gx, 32)); ms.Write(ToBe(c.Gy, 32));
            ms.Write(ToBe(px, 32)); ms.Write(ToBe(py, 32));
            return SM3.ComputeHash(ms.ToArray());
        }

        /// <summary>Sign message with SM2; returns (r, s) each 32 bytes big-endian.</summary>
        public static (byte[] r, byte[] s) Sign(Curve c, byte[] privateKey, byte[] message, string id)
        {
            var d = FromBe(privateKey);
            var pub = Multiply(c, d, (c.Gx, c.Gy))!.Value;
            byte[] z = ComputeZ(c, id, pub.x, pub.y);
            byte[] em = new byte[z.Length + message.Length];
            Buffer.BlockCopy(z, 0, em, 0, z.Length);
            Buffer.BlockCopy(message, 0, em, z.Length, message.Length);
            var e = FromBe(SM3.ComputeHash(em));

            while (true)
            {
                var k = RandomScalar(c.N);
                var p1 = Multiply(c, k, (c.Gx, c.Gy))!.Value;
                var r = Mod(e + p1.x, c.N);
                if (r.IsZero || r + k == c.N) continue;
                var s = Mod(ModInv(1 + d, c.N) * Mod(k - r * d, c.N), c.N);
                if (s.IsZero) continue;
                return (ToBe(r, 32), ToBe(s, 32));
            }
        }

        /// <summary>Verify an SM2 signature. publicKey = X(32)‖Y(32) big-endian.</summary>
        public static bool Verify(Curve c, byte[] publicKey, byte[] message, byte[] rBytes, byte[] sBytes, string id)
        {
            var r = FromBe(rBytes);
            var s = FromBe(sBytes);
            if (r < 1 || r >= c.N || s < 1 || s >= c.N) return false;
            var px = FromBe(publicKey[..32]);
            var py = FromBe(publicKey[32..64]);

            byte[] z = ComputeZ(c, id, px, py);
            byte[] em = new byte[z.Length + message.Length];
            Buffer.BlockCopy(z, 0, em, 0, z.Length);
            Buffer.BlockCopy(message, 0, em, z.Length, message.Length);
            var e = FromBe(SM3.ComputeHash(em));

            var t = Mod(r + s, c.N);
            if (t.IsZero) return false;
            var point = Add(c, Multiply(c, s, (c.Gx, c.Gy)), Multiply(c, t, (px, py)));
            if (point is null) return false;
            return Mod(e + point.Value.x, c.N) == r;
        }

        /// <summary>Generate an SM2 keypair on sm2p256v1. priv = d(32 BE); pub = X(32)‖Y(32) BE.</summary>
        public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair(Curve? curve = null)
        {
            var c = curve ?? Sm2P256;
            var d = RandomScalar(c.N);
            var q = Multiply(c, d, (c.Gx, c.Gy))!.Value;
            byte[] pub = new byte[64];
            Buffer.BlockCopy(ToBe(q.x, 32), 0, pub, 0, 32);
            Buffer.BlockCopy(ToBe(q.y, 32), 0, pub, 32, 32);
            return (ToBe(d, 32), pub);
        }

        /// <summary>Generate an ephemeral SM2 ECDHE keypair for TLS. priv = d(32 BE); pub = 0x04‖X‖Y (65 B).</summary>
        public static (byte[] priv, byte[] pub) EcdhGenerateKeyPair()
        {
            var (d, xy) = GenerateKeyPair();
            byte[] pub = new byte[65];
            pub[0] = 0x04;
            Buffer.BlockCopy(xy, 0, pub, 1, 64);
            return (d, pub);
        }

        /// <summary>ECDHE shared secret = X-coordinate (32 BE) of d·Q_peer. peerPub = 0x04‖X‖Y.</summary>
        public static byte[] EcdhSharedSecret(byte[] privateKey, byte[] peerPub)
        {
            if (peerPub.Length != 65 || peerPub[0] != 0x04)
                throw new TlsException(AlertDescription.IllegalParameter, "Invalid SM2 key_share");
            var c = Sm2P256;
            var px = FromBe(peerPub[1..33]);
            var py = FromBe(peerPub[33..65]);
            var p = Multiply(c, FromBe(privateKey), (px, py))!.Value;
            return ToBe(p.x, 32);
        }

        /// <summary>Compute the public key point X(32)‖Y(32) from a private scalar.</summary>
        public static byte[] DerivePublicKey(Curve c, byte[] privateKey)
        {
            var q = Multiply(c, FromBe(privateKey), (c.Gx, c.Gy))!.Value;
            byte[] pub = new byte[64];
            Buffer.BlockCopy(ToBe(q.x, 32), 0, pub, 0, 32);
            Buffer.BlockCopy(ToBe(q.y, 32), 0, pub, 32, 32);
            return pub;
        }

        private static BigInteger RandomScalar(BigInteger n)
        {
            byte[] buf = new byte[32];
            BigInteger k;
            do { RandomNumberGenerator.Fill(buf); k = new BigInteger(buf, isUnsigned: true, isBigEndian: true) % n; }
            while (k.IsZero);
            return k;
        }
    }

    /// <summary>Check if Chinese cipher suite is supported.</summary>
    public static bool IsChineseCipherSuite(CipherSuite suite)
    {
        return suite == CipherSuite.TLS_SM4_GCM_SM3 ||
               suite == CipherSuite.TLS_SM4_CCM_SM3;
    }
}