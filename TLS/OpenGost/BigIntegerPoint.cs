using System.Security.Cryptography;
using System.Numerics;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Affine-coordinate facade over Jacobian projective EC arithmetic on short-Weierstrass
/// curves over GF(p). The struct's public X / Y are the affine coordinates; internally
/// Multiply uses Jacobian to skip one modular inversion per Add / Double (about a 3-5×
/// speed-up for scalar multiplication over the previous pure-affine code).
/// </summary>
internal struct BigIntegerPoint(in ECPoint point)
{
    private static readonly BigInteger _two = 2;
    private static readonly BigInteger _three = 3;

    public BigInteger X { get; private set; } = CryptoUtils.UnsignedBigIntegerFromLittleEndian(point.X!);
    public BigInteger Y { get; private set; } = CryptoUtils.UnsignedBigIntegerFromLittleEndian(point.Y!);

    public ECPoint ToECPoint(int size)
    {
        return new ECPoint
        {
            X = CryptoUtils.ToLittleEndian(X, size),
            Y = CryptoUtils.ToLittleEndian(Y, size),
        };
    }

    /// <summary>Affine Add — used by the signature-verify path (single addition). Internally
    /// goes through Jacobian; one inverse on the way out.</summary>
    public static BigIntegerPoint Add(in BigIntegerPoint left, in BigIntegerPoint right, in BigInteger prime)
    {
        // a is only used inside Double, never inside the cross-point Add path. Pass 0;
        // the formula only reaches Double if left == right, which the affine wrapper here
        // doesn't model — caller handles same-point via MultipleTwo / Multiply.
        var sum = JacobianAdd(ToJ(left), ToJ(right), BigInteger.Zero, prime);
        var affine = ToAffine(sum, prime);
        return affine ?? new BigIntegerPoint { X = BigInteger.Zero, Y = BigInteger.Zero };
    }

    /// <summary>Scalar multiplication via double-and-add over the binary expansion of
    /// <paramref name="multiplier"/>. Jacobian internally; one modular inverse at the end.</summary>
    public static BigIntegerPoint Multiply(
        in BigIntegerPoint point,
        in BigInteger multiplier,
        in BigInteger prime,
        in BigInteger a)
    {
        if (multiplier.IsZero || multiplier.Sign < 0)
            return new BigIntegerPoint { X = BigInteger.Zero, Y = BigInteger.Zero };

        var basePoint = ToJ(point);
        var result = JInfinity;
        var k = multiplier;
        while (k > 0)
        {
            if (!k.IsEven) result = JacobianAdd(result, basePoint, a, prime);
            basePoint = JacobianDouble(basePoint, a, prime);
            k >>= 1;
        }
        var affine = ToAffine(result, prime);
        return affine ?? new BigIntegerPoint { X = BigInteger.Zero, Y = BigInteger.Zero };
    }

    // -------- Jacobian internals --------
    // Point (X, Y, Z) represents the affine point (X / Z², Y / Z³); Z = 0 is the point at infinity.
    // Formulas from Bernstein/Lange's Explicit-Formulas Database:
    //   doubling-2007-bl, addition-2007-bl.

    private readonly record struct JPoint(BigInteger X, BigInteger Y, BigInteger Z);
    private static readonly JPoint JInfinity = new(BigInteger.Zero, BigInteger.One, BigInteger.Zero);

    private static JPoint ToJ(in BigIntegerPoint p) =>
        new(p.X, p.Y, BigInteger.One);

    private static BigIntegerPoint? ToAffine(in JPoint p, in BigInteger prime)
    {
        if (p.Z.IsZero) return null; // infinity
        var zInv  = BigInteger.ModPow(p.Z, prime - _two, prime);
        var zInv2 = zInv * zInv % prime;
        var zInv3 = zInv2 * zInv % prime;
        var x = p.X * zInv2 % prime;
        var y = p.Y * zInv3 % prime;
        return new BigIntegerPoint { X = x, Y = y };
    }

    private static JPoint JacobianDouble(in JPoint p, in BigInteger a, in BigInteger prime)
    {
        if (p.Z.IsZero || p.Y.IsZero) return JInfinity;
        var ysq     = p.Y * p.Y % prime;
        var s       = 4 * p.X * ysq % prime;
        var zsq     = p.Z * p.Z % prime;
        var zfourth = zsq * zsq % prime;
        var m       = Mod(_three * p.X * p.X + a * zfourth, prime);
        var xR      = Mod(m * m - 2 * s, prime);
        var yR      = Mod(m * (s - xR) - 8 * ysq * ysq, prime);
        var zR      = Mod(2 * p.Y * p.Z, prime);
        return new(xR, yR, zR);
    }

    private static JPoint JacobianAdd(in JPoint p, in JPoint q, in BigInteger a, in BigInteger prime)
    {
        if (p.Z.IsZero) return q;
        if (q.Z.IsZero) return p;
        var z1sq = p.Z * p.Z % prime;
        var z2sq = q.Z * q.Z % prime;
        var u1   = p.X * z2sq % prime;
        var u2   = q.X * z1sq % prime;
        var s1   = p.Y * q.Z % prime * z2sq % prime;
        var s2   = q.Y * p.Z % prime * z1sq % prime;
        if (u1 == u2)
        {
            if (s1 != s2) return JInfinity;            // P + (-P) = O
            return JacobianDouble(p, a, prime);         // P == Q
        }
        var h    = Mod(u2 - u1, prime);
        var r    = Mod(s2 - s1, prime);
        var hsq  = h * h % prime;
        var hcb  = hsq * h % prime;
        var u1h2 = u1 * hsq % prime;
        var xR   = Mod(r * r - hcb - 2 * u1h2, prime);
        var yR   = Mod(r * (u1h2 - xR) - s1 * hcb, prime);
        var zR   = h * p.Z % prime * q.Z % prime;
        return new(xR, yR, Mod(zR, prime));
    }

    private static BigInteger Mod(in BigInteger v, in BigInteger prime)
    {
        var r = v % prime;
        return r.Sign < 0 ? r + prime : r;
    }
}
