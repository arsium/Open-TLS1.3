namespace TLS;

using System.Numerics;
using System.Security.Cryptography;

/// <summary>
/// Pure Ed25519 digital signature scheme (RFC 8032).
/// Edwards curve operations on Curve25519, p = 2^255 − 19.
/// </summary>
public static class Ed25519
{
    // Field prime: p = 2^255 - 19
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;

    // Curve parameter: d = -121665/121666 mod p = -121665 * inverse(121666) mod p
    private static readonly BigInteger D = Mod(-121665 * ModInverse(121666, P));

    // Group order: L = 2^252 + 27742317777372353535851937790883648493
    private static readonly BigInteger L =
        (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    // sqrt(-1) mod p = 2^((p-1)/4) mod p
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

    // Base point B in extended coordinates (X, Y, Z, T)
    private static readonly (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) B = ComputeBasePoint();

    // Neutral element (identity point) in extended coordinates
    private static readonly (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Neutral =
        (BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);

    /// <summary>Generates a 32-byte random seed (private key).</summary>
    public static byte[] GeneratePrivateKey()
    {
        return RandomnessWrapper.GetKeyBytes(32);
    }

    /// <summary>Derives the 32-byte compressed public key from a 32-byte seed.</summary>
    public static byte[] PublicFromPrivate(byte[] seed)
    {
        if (seed.Length != 32)
            throw new ArgumentException("Seed must be 32 bytes.", nameof(seed));

        byte[] h = SHA512(seed);
        ClampScalar(h);
        BigInteger a = DecodeLE(h, 0, 32);

        var A = ScalarMult(a, B);
        return EncodePoint(A);
    }

    /// <summary>Signs a message with the given 32-byte seed. Returns a 64-byte signature.</summary>
    public static byte[] Sign(byte[] message, byte[] seed)
    {
        if (seed.Length != 32)
            throw new ArgumentException("Seed must be 32 bytes.", nameof(seed));

        // Step 1: expand seed
        byte[] h = SHA512(seed);
        byte[] hClamped = new byte[32];
        Buffer.BlockCopy(h, 0, hClamped, 0, 32);
        ClampScalar(hClamped);
        BigInteger a = DecodeLE(hClamped, 0, 32);

        // Public key A = a * B
        var A = ScalarMult(a, B);
        byte[] aBytes = EncodePoint(A);

        // Step 2: r = SHA-512(prefix || message) mod L
        // prefix = h[32..64]
        byte[] rHash = SHA512(Concat(h, 32, 32, message, 0, message.Length));
        BigInteger r = Mod(DecodeLE(rHash, 0, 64), L);

        // Step 3: R = r * B
        var R = ScalarMult(r, B);
        byte[] rBytes = EncodePoint(R);

        // Step 4: S = (r + SHA-512(R || A || message) * a) mod L
        byte[] kHash = SHA512(Concat3(rBytes, aBytes, message));
        BigInteger k = Mod(DecodeLE(kHash, 0, 64), L);
        BigInteger s = Mod(r + k * a, L);

        // Signature = R || S (64 bytes)
        byte[] signature = new byte[64];
        Buffer.BlockCopy(rBytes, 0, signature, 0, 32);
        byte[] sBytes = EncodeLE(s, 32);
        Buffer.BlockCopy(sBytes, 0, signature, 32, 32);
        return signature;
    }

    /// <summary>Verifies an Ed25519 signature. Returns true if valid.</summary>
    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (signature.Length != 64 || publicKey.Length != 32)
            return false;

        // Decode R from first 32 bytes of signature
        var R = DecodePoint(signature, 0);
        if (R == null) return false;

        // Decode S from last 32 bytes of signature
        BigInteger s = DecodeLE(signature, 32, 32);
        if (s >= L) return false;

        // Decode public key A
        var A = DecodePoint(publicKey, 0);
        if (A == null) return false;

        // h = SHA-512(R_bytes || A_bytes || message) mod L
        byte[] rBytes = new byte[32];
        Buffer.BlockCopy(signature, 0, rBytes, 0, 32);
        byte[] kHash = SHA512(Concat3(rBytes, publicKey, message));
        BigInteger h = Mod(DecodeLE(kHash, 0, 64), L);

        // Check: S * B == R + h * A
        var lhs = ScalarMult(s, B);
        var rhs = PointAdd(R.Value, ScalarMult(h, A.Value));

        return PointEqual(lhs, rhs);
    }

    // ────────────────────────────── Point operations (extended coordinates) ──────────────────────────────

    /// <summary>Point addition on the twisted Edwards curve using extended coordinates.</summary>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) PointAdd(
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p1,
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p2)
    {
        // RFC 8032 / Hisil et al. "Twisted Edwards Curves Revisited"
        BigInteger a = Mod(p1.X * p2.X);
        BigInteger b = Mod(p1.Y * p2.Y);
        BigInteger c = Mod(p1.T * D * p2.T);
        BigInteger d = Mod(p1.Z * p2.Z);
        BigInteger e = Mod((p1.X + p1.Y) * (p2.X + p2.Y) - a - b);
        BigInteger f = Mod(d - c);
        BigInteger g = Mod(d + c);
        BigInteger h = Mod(b + a);  // note: curve is -x^2 + y^2 = ..., so a_coeff = -1, thus b - (-1)*a = b + a

        BigInteger X3 = Mod(e * f);
        BigInteger Y3 = Mod(g * h);
        BigInteger T3 = Mod(e * h);
        BigInteger Z3 = Mod(f * g);

        return (X3, Y3, Z3, T3);
    }

    /// <summary>Point doubling on the twisted Edwards curve using extended coordinates (dbl-2008-hwcd, a=-1).</summary>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) PointDouble(
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p)
    {
        // A=X^2, B=Y^2, C=2Z^2, D=a*A=-A, E=(X+Y)^2-A-B, G=D+B, F=G-C, H=D-B
        BigInteger a = Mod(p.X * p.X);
        BigInteger b = Mod(p.Y * p.Y);
        BigInteger c = Mod(2 * p.Z * p.Z);
        BigInteger e = Mod(Mod((p.X + p.Y) * (p.X + p.Y)) - a - b);
        BigInteger g = Mod(-a + b);   // G = D + B where D = -A (a_coeff = -1)
        BigInteger f = Mod(g - c);    // F = G - C
        BigInteger h = Mod(-a - b);   // H = D - B

        BigInteger X3 = Mod(e * f);
        BigInteger Y3 = Mod(g * h);
        BigInteger T3 = Mod(e * h);
        BigInteger Z3 = Mod(f * g);

        return (X3, Y3, Z3, T3);
    }

    /// <summary>Scalar multiplication using double-and-add (constant-time is not needed for signatures).</summary>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) ScalarMult(
        BigInteger n,
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) point)
    {
        n = Mod(n, L);
        if (n == BigInteger.Zero)
            return Neutral;

        var result = Neutral;
        var current = point;

        while (n > 0)
        {
            if (!n.IsEven)
                result = PointAdd(result, current);

            current = PointDouble(current);
            n >>= 1;
        }

        return result;
    }

    /// <summary>Checks if two points in extended coordinates are equal (projective comparison).</summary>
    private static bool PointEqual(
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p1,
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p2)
    {
        // X1/Z1 == X2/Z2  =>  X1*Z2 == X2*Z1
        // Y1/Z1 == Y2/Z2  =>  Y1*Z2 == Y2*Z1
        return Mod(p1.X * p2.Z) == Mod(p2.X * p1.Z)
            && Mod(p1.Y * p2.Z) == Mod(p2.Y * p1.Z);
    }

    // ────────────────────────────── Encoding / Decoding ──────────────────────────────

    /// <summary>Encodes a point as a 32-byte compressed Edwards point.</summary>
    private static byte[] EncodePoint((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) pt)
    {
        BigInteger zinv = ModInverse(pt.Z, P);
        BigInteger x = Mod(pt.X * zinv);
        BigInteger y = Mod(pt.Y * zinv);

        byte[] encoded = EncodeLE(y, 32);
        // Set the top bit of the last byte to the low bit of x
        encoded[31] |= (byte)((x & 1) == 1 ? 0x80 : 0x00);
        return encoded;
    }

    /// <summary>
    /// Decodes a 32-byte compressed Edwards point.
    /// Returns null if the point is not on the curve.
    /// </summary>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T)? DecodePoint(byte[] data, int offset)
    {
        byte[] yBytes = new byte[32];
        Buffer.BlockCopy(data, offset, yBytes, 0, 32);

        // Extract x sign bit from top bit of last byte
        int xBit = (yBytes[31] >> 7) & 1;
        yBytes[31] &= 0x7F; // clear the sign bit

        BigInteger y = DecodeLE(yBytes, 0, 32);
        if (y >= P) return null;

        // Recover x from the curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
        // x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
        BigInteger y2 = Mod(y * y);
        BigInteger num = Mod(y2 - 1);
        BigInteger den = Mod(D * y2 + 1);

        BigInteger denInv = ModInverse(den, P);
        BigInteger x2 = Mod(num * denInv);

        if (x2 == BigInteger.Zero)
        {
            if (xBit != 0) return null;
            return (BigInteger.Zero, y, BigInteger.One, BigInteger.Zero);
        }

        // x = x2^((p+3)/8) mod p
        BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);

        // If x^2 != x2, multiply x by sqrt(-1)
        if (Mod(x * x) != x2)
        {
            x = Mod(x * SqrtM1);
            if (Mod(x * x) != x2)
                return null; // no square root exists; not a valid point
        }

        // Adjust sign: if x is odd but xBit is 0 (or vice versa), negate
        if (((int)(x & 1)) != xBit)
            x = Mod(P - x);

        BigInteger t = Mod(x * y);
        return (x, y, BigInteger.One, t);
    }

    // ────────────────────────────── Base point computation ──────────────────────────────

    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) ComputeBasePoint()
    {
        BigInteger p = (BigInteger.One << 255) - 19;
        BigInteger d = Mod(-121665 * ModInverse(121666, p), p);

        // By = 4/5 mod p = 4 * inverse(5, p) mod p
        BigInteger By = Mod(4 * ModInverse(5, p), p);

        // Recover Bx from curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
        BigInteger y2 = Mod(By * By, p);
        BigInteger num = Mod(y2 - 1, p);
        BigInteger den = Mod(d * y2 + 1, p);
        BigInteger x2 = Mod(num * ModInverse(den, p), p);

        BigInteger Bx = BigInteger.ModPow(x2, (p + 3) / 8, p);
        if (Mod(Bx * Bx, p) != x2)
            Bx = Mod(Bx * BigInteger.ModPow(2, (p - 1) / 4, p), p);

        // Pick the even x (least significant bit = 0)
        if (!Bx.IsEven)
            Bx = Mod(p - Bx, p);

        return (Bx, By, BigInteger.One, Mod(Bx * By, p));
    }

    // ────────────────────────────── Scalar clamping ──────────────────────────────

    private static void ClampScalar(byte[] h)
    {
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;
    }

    // ────────────────────────────── Modular arithmetic helpers ──────────────────────────────

    /// <summary>Reduces v modulo the field prime P.</summary>
    private static BigInteger Mod(BigInteger v)
    {
        BigInteger r = v % P;
        return r < 0 ? r + P : r;
    }

    /// <summary>Reduces v modulo an arbitrary modulus m.</summary>
    private static BigInteger Mod(BigInteger v, BigInteger m)
    {
        BigInteger r = v % m;
        return r < 0 ? r + m : r;
    }

    /// <summary>Computes the modular inverse a^(-1) mod m using Fermat's little theorem (m must be prime).</summary>
    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        a = ((a % m) + m) % m;
        return BigInteger.ModPow(a, m - 2, m);
    }

    // ────────────────────────────── Byte helpers (same pattern as X25519) ──────────────────────────────

    private static BigInteger DecodeLE(byte[] b, int offset, int count)
    {
        byte[] padded = new byte[count + 1]; // extra zero byte ensures unsigned interpretation
        Buffer.BlockCopy(b, offset, padded, 0, count);
        return new BigInteger(padded);
    }

    private static byte[] EncodeLE(BigInteger v, int size)
    {
        byte[] raw = v.ToByteArray(); // .NET BigInteger is little-endian
        byte[] result = new byte[size];
        int len = Math.Min(raw.Length, size);
        if (raw.Length > size && raw[^1] == 0) len = size;
        Buffer.BlockCopy(raw, 0, result, 0, len);
        return result;
    }

    private static byte[] SHA512(byte[] data)
    {
        return Sha2Managed.Sha512(data);
    }

    /// <summary>Concatenates a slice of a with a slice of b.</summary>
    private static byte[] Concat(byte[] a, int aOffset, int aLen, byte[] b, int bOffset, int bLen)
    {
        byte[] result = new byte[aLen + bLen];
        Buffer.BlockCopy(a, aOffset, result, 0, aLen);
        Buffer.BlockCopy(b, bOffset, result, aLen, bLen);
        return result;
    }

    /// <summary>Concatenates three full byte arrays.</summary>
    private static byte[] Concat3(byte[] a, byte[] b, byte[] c)
    {
        byte[] result = new byte[a.Length + b.Length + c.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
        return result;
    }
}
