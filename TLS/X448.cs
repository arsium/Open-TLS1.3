namespace TLS;

using System.Numerics;
using System.Security.Cryptography;

public static class X448
{
    private static readonly BigInteger P = (BigInteger.One << 448) - (BigInteger.One << 224) - 1;
    private static readonly BigInteger A24 = 39081;

    public static byte[] GeneratePrivateKey()
    {
        byte[] key = RandomNumberGenerator.GetBytes(56);
        Clamp(key);
        return key;
    }

    public static byte[] PublicFromPrivate(byte[] privateKey)
    {
        byte[] basePoint = new byte[56];
        basePoint[0] = 5;
        return ScalarMult(privateKey, basePoint);
    }

    public static byte[] SharedSecret(byte[] myPrivate, byte[] theirPublic)
    {
        byte[] result = ScalarMult(myPrivate, theirPublic);
        bool allZero = true;
        for (int i = 0; i < result.Length; i++)
            if (result[i] != 0) { allZero = false; break; }
        if (allZero)
            throw new TlsException(AlertDescription.IllegalParameter, "X448 produced all-zero shared secret");
        return result;
    }

    private static void Clamp(byte[] k)
    {
        k[0] &= 252;
        k[55] |= 128;
    }

    private static byte[] ScalarMult(byte[] scalar, byte[] uBytes)
    {
        byte[] k = (byte[])scalar.Clone();
        Clamp(k);
        BigInteger kInt = DecodeLE(k);
        BigInteger u = DecodeLE(uBytes);
        u &= (BigInteger.One << 448) - 1;

        BigInteger x_1 = u;
        BigInteger x_2 = BigInteger.One, z_2 = BigInteger.Zero;
        BigInteger x_3 = u, z_3 = BigInteger.One;
        bool swap = false;

        for (int t = 447; t >= 0; t--)
        {
            bool kt = ((kInt >> t) & 1) == 1;
            swap ^= kt;
            if (swap) { (x_2, x_3) = (x_3, x_2); (z_2, z_3) = (z_3, z_2); }
            swap = kt;

            BigInteger A = Mod(x_2 + z_2);
            BigInteger AA = Mod(A * A);
            BigInteger B = Mod(x_2 - z_2);
            BigInteger BB = Mod(B * B);
            BigInteger E = Mod(AA - BB);
            BigInteger C = Mod(x_3 + z_3);
            BigInteger D = Mod(x_3 - z_3);
            BigInteger DA = Mod(D * A);
            BigInteger CB = Mod(C * B);
            x_3 = Mod(Mod(DA + CB) * Mod(DA + CB));
            z_3 = Mod(x_1 * Mod(Mod(DA - CB) * Mod(DA - CB)));
            x_2 = Mod(AA * BB);
            z_2 = Mod(E * Mod(AA + A24 * E));
        }

        if (swap) { (x_2, x_3) = (x_3, x_2); (z_2, z_3) = (z_3, z_2); }
        BigInteger result = Mod(x_2 * BigInteger.ModPow(z_2, P - 2, P));
        return EncodeLE(result, 56);
    }

    private static BigInteger Mod(BigInteger v)
    {
        BigInteger r = v % P;
        return r < 0 ? r + P : r;
    }

    private static BigInteger DecodeLE(byte[] b)
    {
        byte[] padded = new byte[b.Length + 1];
        Buffer.BlockCopy(b, 0, padded, 0, b.Length);
        return new BigInteger(padded);
    }

    private static byte[] EncodeLE(BigInteger v, int size)
    {
        byte[] raw = v.ToByteArray();
        byte[] result = new byte[size];
        int len = Math.Min(raw.Length, size);
        if (raw.Length > size && raw[^1] == 0) len = size;
        Buffer.BlockCopy(raw, 0, result, 0, len);
        return result;
    }
}
