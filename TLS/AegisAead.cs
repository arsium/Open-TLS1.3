namespace TLS;

using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

/// <summary>
/// AEGIS-128L and AEGIS-256 authenticated encryption (draft-irtf-cfrg-aegis-aead-18),
/// for the TLS 1.3 cipher suites in draft-denis-tls-aegis-06
/// (TLS_AEGIS_256_SHA512 = 0x1306, TLS_AEGIS_128L_SHA256 = 0x1307).
///
/// NOTE: AEGIS is Internet-Draft-stage in BOTH its algorithm (draft-irtf-cfrg-aegis-aead) and its TLS
/// suites (draft-denis-tls-aegis) — neither is a finalized RFC. The code points and wire details may
/// change before publication; treat as experimental and KAT-verified against the current drafts only.
///
/// Pure-managed: the AES round is taken from the x86 AES-NI (<c>AESENC</c>) or ARMv8 crypto
/// (<c>AESE</c>+<c>AESMC</c>) JIT intrinsics when available, with a software FIPS-197 round as a
/// portable fallback — no BCrypt/OpenSSL P/Invoke. The TLS suites always use a 128-bit tag.
/// </summary>
public sealed class AegisAead : IDisposable
{
    /// <summary>AEGIS tag length used by the TLS suites (draft-denis-tls-aegis §3): 16 bytes.</summary>
    public const int TagLength = 16;

    private readonly byte[] _key;
    private readonly bool _is256;

    public AegisAead(byte[] key, bool is256)
    {
        int expected = is256 ? 32 : 16;
        if (key.Length != expected)
            throw new ArgumentException($"AEGIS-{(is256 ? 256 : "128L")} key must be {expected} bytes", nameof(key));
        _key = (byte[])key.Clone();
        _is256 = is256;
    }

    /// <summary>Encrypt into <paramref name="output"/> = ciphertext (plaintext.Length) ‖ tag (16).</summary>
    public void EncryptInto(byte[] nonce, ReadOnlySpan<byte> plaintext, Span<byte> output, ReadOnlySpan<byte> aad)
    {
        if (output.Length != plaintext.Length + TagLength)
            throw new ArgumentException($"output must be plaintext.Length + {TagLength} bytes");
        var ct = output.Slice(0, plaintext.Length);
        var tag = output.Slice(plaintext.Length, TagLength);
        if (_is256) Aegis256.Encrypt(_key, nonce, aad, plaintext, ct, tag);
        else Aegis128L.Encrypt(_key, nonce, aad, plaintext, ct, tag);
    }

    /// <summary>Decrypt <paramref name="encrypted"/> = ciphertext ‖ tag (16). Returns false on tag
    /// mismatch (the plaintext buffer is zeroed first), matching the suite's trial-decrypt semantics.</summary>
    public bool TryDecryptInto(byte[] nonce, ReadOnlySpan<byte> encrypted, Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        int ctLen = encrypted.Length - TagLength;
        if (ctLen < 0 || plaintext.Length != ctLen) return false;
        var ct = encrypted.Slice(0, ctLen);
        var tag = encrypted.Slice(ctLen, TagLength);
        return _is256
            ? Aegis256.Decrypt(_key, nonce, aad, ct, tag, plaintext)
            : Aegis128L.Decrypt(_key, nonce, aad, ct, tag, plaintext);
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);

    // ================================================================
    //  Shared primitives (§2)
    // ================================================================

    /// <summary>Test hook: force the software AES round even when AES intrinsics are available,
    /// so the portable fallback can be KAT-validated on hardware that has AES-NI.</summary>
    internal static bool ForceSoftwareAes { get; set; }

    // C0/C1 (§2). Lane 0 holds the first byte, matching the byte arrays in the spec.
    internal static readonly Vector128<byte> C0 = Vector128.Create(
        (byte)0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62);
    internal static readonly Vector128<byte> C1 = Vector128.Create(
        (byte)0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd);

    /// <summary>AESRound(in, rk): one AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey) — §2.</summary>
    internal static Vector128<byte> AesRound(Vector128<byte> state, Vector128<byte> rk)
    {
        if (!ForceSoftwareAes)
        {
            if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
                return System.Runtime.Intrinsics.X86.Aes.Encrypt(state, rk);
            if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
                // x86 AESENC(s,rk) == MixColumns(SubBytes(ShiftRows(s))) ^ rk.
                // ARM AESE(s,0) = SubBytes(ShiftRows(s)); AESMC = MixColumns. SubBytes/ShiftRows commute.
                return System.Runtime.Intrinsics.Arm.Aes.MixColumns(
                           System.Runtime.Intrinsics.Arm.Aes.Encrypt(state, Vector128<byte>.Zero)) ^ rk;
        }
        return SoftAesRound(state, rk);
    }

    private static Vector128<byte> SoftAesRound(Vector128<byte> state, Vector128<byte> rk)
    {
        Span<byte> s = stackalloc byte[16];
        state.StoreUnsafe(ref s[0]);

        // SubBytes
        for (int i = 0; i < 16; i++) s[i] = Sbox[s[i]];

        // ShiftRows (column-major state, byte index = 4*col + row; row r rotates left by r)
        Span<byte> t = stackalloc byte[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                t[(c << 2) + r] = s[(((c + r) & 3) << 2) + r];

        // MixColumns + AddRoundKey
        Span<byte> o = stackalloc byte[16];
        for (int c = 0; c < 4; c++)
        {
            int b = c << 2;
            byte a0 = t[b], a1 = t[b + 1], a2 = t[b + 2], a3 = t[b + 3];
            o[b]     = (byte)(Xtime(a0) ^ Xtime(a1) ^ a1 ^ a2 ^ a3);
            o[b + 1] = (byte)(a0 ^ Xtime(a1) ^ Xtime(a2) ^ a2 ^ a3);
            o[b + 2] = (byte)(a0 ^ a1 ^ Xtime(a2) ^ Xtime(a3) ^ a3);
            o[b + 3] = (byte)(Xtime(a0) ^ a0 ^ a1 ^ a2 ^ Xtime(a3));
        }
        return Vector128.LoadUnsafe(ref o[0]) ^ rk;
    }

    private static byte Xtime(byte x) => (byte)((x << 1) ^ (((x >> 7) & 1) * 0x1b));

    // Load/store exactly one 128-bit block from the start of the span. Vector128.Create/CopyTo
    // read/write the first 16 bytes (the span may be longer, e.g. a 32-byte rate buffer).
    private static Vector128<byte> Ld(ReadOnlySpan<byte> s) => Vector128.Create(s.Slice(0, 16));
    private static void St(Vector128<byte> v, Span<byte> s) => v.CopyTo(s.Slice(0, 16));

    // LE64(ad_len_bits) || LE64(msg_len_bits) as a 128-bit block.
    private static Vector128<byte> LenBlock(ulong adBits, ulong msgBits)
    {
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(b, adBits);
        BinaryPrimitives.WriteUInt64LittleEndian(b.Slice(8), msgBits);
        return Ld(b);
    }

    // ================================================================
    //  AEGIS-128L (§3): 1024-bit state {S0..S7}, 256-bit input blocks
    // ================================================================
    private static class Aegis128L
    {
        private static void Update(Span<Vector128<byte>> s, Vector128<byte> m0, Vector128<byte> m1)
        {
            var n0 = AesRound(s[7], s[0] ^ m0);
            var n1 = AesRound(s[0], s[1]);
            var n2 = AesRound(s[1], s[2]);
            var n3 = AesRound(s[2], s[3]);
            var n4 = AesRound(s[3], s[4] ^ m1);
            var n5 = AesRound(s[4], s[5]);
            var n6 = AesRound(s[5], s[6]);
            var n7 = AesRound(s[6], s[7]);
            s[0] = n0; s[1] = n1; s[2] = n2; s[3] = n3; s[4] = n4; s[5] = n5; s[6] = n6; s[7] = n7;
        }

        private static void Init(Span<Vector128<byte>> s, byte[] key, byte[] nonce)
        {
            var k = Ld(key);
            var n = Ld(nonce);
            s[0] = k ^ n; s[1] = C1; s[2] = C0; s[3] = C1;
            s[4] = k ^ n; s[5] = k ^ C0; s[6] = k ^ C1; s[7] = k ^ C0;
            for (int i = 0; i < 10; i++) Update(s, n, k);
        }

        private static void Absorb(Span<Vector128<byte>> s, ReadOnlySpan<byte> ad)
        {
            int i = 0;
            for (; i + 32 <= ad.Length; i += 32)
                Update(s, Ld(ad.Slice(i, 16)), Ld(ad.Slice(i + 16, 16)));
            int rem = ad.Length - i;
            if (rem > 0)
            {
                Span<byte> blk = stackalloc byte[32];
                blk.Clear();
                ad.Slice(i, rem).CopyTo(blk);
                Update(s, Ld(blk), Ld(blk.Slice(16)));
            }
        }

        public static void Encrypt(byte[] key, byte[] nonce, ReadOnlySpan<byte> ad,
            ReadOnlySpan<byte> msg, Span<byte> ct, Span<byte> tag)
        {
            Span<Vector128<byte>> s = stackalloc Vector128<byte>[8];
            Init(s, key, nonce);
            Absorb(s, ad);

            int i = 0;
            for (; i + 32 <= msg.Length; i += 32)
            {
                var t0 = Ld(msg.Slice(i, 16)); var t1 = Ld(msg.Slice(i + 16, 16));
                var z0 = s[1] ^ s[6] ^ (s[2] & s[3]);
                var z1 = s[2] ^ s[5] ^ (s[6] & s[7]);
                Update(s, t0, t1);
                St(t0 ^ z0, ct.Slice(i, 16)); St(t1 ^ z1, ct.Slice(i + 16, 16));
            }
            int rem = msg.Length - i;
            if (rem > 0)
            {
                Span<byte> blk = stackalloc byte[32]; blk.Clear();
                msg.Slice(i, rem).CopyTo(blk);
                var t0 = Ld(blk); var t1 = Ld(blk.Slice(16));
                var z0 = s[1] ^ s[6] ^ (s[2] & s[3]);
                var z1 = s[2] ^ s[5] ^ (s[6] & s[7]);
                Update(s, t0, t1);
                Span<byte> ob = stackalloc byte[32];
                St(t0 ^ z0, ob); St(t1 ^ z1, ob.Slice(16));
                ob.Slice(0, rem).CopyTo(ct.Slice(i, rem));
            }

            St(Finalize(s, (ulong)ad.Length * 8, (ulong)msg.Length * 8), tag);
        }

        public static bool Decrypt(byte[] key, byte[] nonce, ReadOnlySpan<byte> ad,
            ReadOnlySpan<byte> ct, ReadOnlySpan<byte> tag, Span<byte> msg)
        {
            Span<Vector128<byte>> s = stackalloc Vector128<byte>[8];
            Init(s, key, nonce);
            Absorb(s, ad);

            int i = 0;
            for (; i + 32 <= ct.Length; i += 32)
            {
                var z0 = s[1] ^ s[6] ^ (s[2] & s[3]);
                var z1 = s[2] ^ s[5] ^ (s[6] & s[7]);
                var o0 = Ld(ct.Slice(i, 16)) ^ z0;
                var o1 = Ld(ct.Slice(i + 16, 16)) ^ z1;
                Update(s, o0, o1);
                St(o0, msg.Slice(i, 16)); St(o1, msg.Slice(i + 16, 16));
            }
            int rem = ct.Length - i;
            if (rem > 0)
            {
                var z0 = s[1] ^ s[6] ^ (s[2] & s[3]);
                var z1 = s[2] ^ s[5] ^ (s[6] & s[7]);
                Span<byte> blk = stackalloc byte[32]; blk.Clear();
                ct.Slice(i, rem).CopyTo(blk);
                Span<byte> ob = stackalloc byte[32];
                St(Ld(blk) ^ z0, ob); St(Ld(blk.Slice(16)) ^ z1, ob.Slice(16));
                ob.Slice(rem).Clear(); // ZeroPad(xn, 256)
                Update(s, Ld(ob), Ld(ob.Slice(16)));
                ob.Slice(0, rem).CopyTo(msg.Slice(i, rem));
            }

            Span<byte> expected = stackalloc byte[TagLength];
            St(Finalize(s, (ulong)ad.Length * 8, (ulong)ct.Length * 8), expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            {
                CryptographicOperations.ZeroMemory(msg);
                return false;
            }
            return true;
        }

        private static Vector128<byte> Finalize(Span<Vector128<byte>> s, ulong adBits, ulong msgBits)
        {
            var t = s[2] ^ LenBlock(adBits, msgBits);
            for (int i = 0; i < 7; i++) Update(s, t, t);
            return s[0] ^ s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5] ^ s[6];
        }
    }

    // ================================================================
    //  AEGIS-256 (§4): 768-bit state {S0..S5}, 128-bit input blocks
    // ================================================================
    private static class Aegis256
    {
        private static void Update(Span<Vector128<byte>> s, Vector128<byte> m)
        {
            var n0 = AesRound(s[5], s[0] ^ m);
            var n1 = AesRound(s[0], s[1]);
            var n2 = AesRound(s[1], s[2]);
            var n3 = AesRound(s[2], s[3]);
            var n4 = AesRound(s[3], s[4]);
            var n5 = AesRound(s[4], s[5]);
            s[0] = n0; s[1] = n1; s[2] = n2; s[3] = n3; s[4] = n4; s[5] = n5;
        }

        private static void Init(Span<Vector128<byte>> s, byte[] key, byte[] nonce)
        {
            var k0 = Ld(key.AsSpan(0, 16)); var k1 = Ld(key.AsSpan(16, 16));
            var n0 = Ld(nonce.AsSpan(0, 16)); var n1 = Ld(nonce.AsSpan(16, 16));
            s[0] = k0 ^ n0; s[1] = k1 ^ n1; s[2] = C1; s[3] = C0; s[4] = k0 ^ C0; s[5] = k1 ^ C1;
            for (int i = 0; i < 4; i++)
            {
                Update(s, k0); Update(s, k1); Update(s, k0 ^ n0); Update(s, k1 ^ n1);
            }
        }

        private static void Absorb(Span<Vector128<byte>> s, ReadOnlySpan<byte> ad)
        {
            int i = 0;
            for (; i + 16 <= ad.Length; i += 16) Update(s, Ld(ad.Slice(i, 16)));
            int rem = ad.Length - i;
            if (rem > 0)
            {
                Span<byte> blk = stackalloc byte[16]; blk.Clear();
                ad.Slice(i, rem).CopyTo(blk);
                Update(s, Ld(blk));
            }
        }

        public static void Encrypt(byte[] key, byte[] nonce, ReadOnlySpan<byte> ad,
            ReadOnlySpan<byte> msg, Span<byte> ct, Span<byte> tag)
        {
            Span<Vector128<byte>> s = stackalloc Vector128<byte>[6];
            Init(s, key, nonce);
            Absorb(s, ad);

            int i = 0;
            for (; i + 16 <= msg.Length; i += 16)
            {
                var z = s[1] ^ s[4] ^ s[5] ^ (s[2] & s[3]);
                var xi = Ld(msg.Slice(i, 16));
                Update(s, xi);
                St(xi ^ z, ct.Slice(i, 16));
            }
            int rem = msg.Length - i;
            if (rem > 0)
            {
                var z = s[1] ^ s[4] ^ s[5] ^ (s[2] & s[3]);
                Span<byte> blk = stackalloc byte[16]; blk.Clear();
                msg.Slice(i, rem).CopyTo(blk);
                var xi = Ld(blk);
                Update(s, xi);
                Span<byte> ob = stackalloc byte[16];
                St(xi ^ z, ob);
                ob.Slice(0, rem).CopyTo(ct.Slice(i, rem));
            }

            St(Finalize(s, (ulong)ad.Length * 8, (ulong)msg.Length * 8), tag);
        }

        public static bool Decrypt(byte[] key, byte[] nonce, ReadOnlySpan<byte> ad,
            ReadOnlySpan<byte> ct, ReadOnlySpan<byte> tag, Span<byte> msg)
        {
            Span<Vector128<byte>> s = stackalloc Vector128<byte>[6];
            Init(s, key, nonce);
            Absorb(s, ad);

            int i = 0;
            for (; i + 16 <= ct.Length; i += 16)
            {
                var z = s[1] ^ s[4] ^ s[5] ^ (s[2] & s[3]);
                var xi = Ld(ct.Slice(i, 16)) ^ z;
                Update(s, xi);
                St(xi, msg.Slice(i, 16));
            }
            int rem = ct.Length - i;
            if (rem > 0)
            {
                var z = s[1] ^ s[4] ^ s[5] ^ (s[2] & s[3]);
                Span<byte> blk = stackalloc byte[16]; blk.Clear();
                ct.Slice(i, rem).CopyTo(blk);
                Span<byte> ob = stackalloc byte[16];
                St(Ld(blk) ^ z, ob);
                ob.Slice(rem).Clear(); // ZeroPad(xn, 128)
                Update(s, Ld(ob));
                ob.Slice(0, rem).CopyTo(msg.Slice(i, rem));
            }

            Span<byte> expected = stackalloc byte[TagLength];
            St(Finalize(s, (ulong)ad.Length * 8, (ulong)ct.Length * 8), expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            {
                CryptographicOperations.ZeroMemory(msg);
                return false;
            }
            return true;
        }

        private static Vector128<byte> Finalize(Span<Vector128<byte>> s, ulong adBits, ulong msgBits)
        {
            var t = s[3] ^ LenBlock(adBits, msgBits);
            for (int i = 0; i < 7; i++) Update(s, t);
            return s[0] ^ s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5];
        }
    }

    // Standard AES S-box (FIPS-197), used only by the software AES-round fallback.
    private static readonly byte[] Sbox =
    {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };
}
