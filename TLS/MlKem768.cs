namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// ML-KEM-768 (formerly CRYSTALS-Kyber-768) key encapsulation mechanism (FIPS 203).
/// Post-quantum lattice-based KEM for hybrid key exchange in TLS 1.3.
/// Parameters: n=256, k=3, q=3329, eta1=2, eta2=2, du=10, dv=4.
/// </summary>
public static class MlKem768
{
    // ML-KEM-768 parameters
    private const int N = 256;   // polynomial degree
    private const int K = 3;     // module rank
    private const int Q = 3329;  // modulus
    private const int Eta1 = 2;  // CBD noise parameter for secret/randomness vectors
    private const int Eta2 = 2;  // CBD noise parameter for error terms
    private const int Du = 10;   // compression bits for u vector
    private const int Dv = 4;    // compression bits for v scalar

    // Derived sizes
    private const int PolyBytes = 384;              // 12 bits * 256 / 8 = 384 bytes per uncompressed polynomial
    private const int PolyVecBytes = K * PolyBytes;  // 1152 bytes for k=3
    private const int EkSize = PolyVecBytes + 32;    // 1184 bytes (encoded t_hat || rho)
    private const int DkSize = PolyVecBytes + EkSize + 32 + 32; // 2400 bytes
    private const int CompressedPolyDu = N * Du / 8; // 320 bytes per compressed polynomial (du=10)
    private const int CompressedPolyDv = N * Dv / 8; // 128 bytes for compressed v (dv=4)
    private const int CiphertextSize = K * CompressedPolyDu + CompressedPolyDv; // 1088 bytes

    // Precomputed NTT zeta powers in bit-reversed order
    // zeta = 17 is a primitive 256th root of unity mod 3329
    private static readonly short[] Zetas = PrecomputeZetas();

    /// <summary>
    /// Generate an ML-KEM-768 key pair.
    /// </summary>
    /// <returns>
    /// encapsulationKey (1184 bytes): the public encapsulation key.
    /// decapsulationKey (2400 bytes): the private decapsulation key.
    /// </returns>
    public static (byte[] encapsulationKey, byte[] decapsulationKey) KeyGen()
    {
        byte[] d = RandomNumberGenerator.GetBytes(32);
        byte[] z = RandomNumberGenerator.GetBytes(32);
        return KeyGenInternal(d, z);
    }

    /// <summary>
    /// Encapsulate a shared secret against an encapsulation key.
    /// </summary>
    /// <param name="encapsulationKey">1184-byte encapsulation key from KeyGen.</param>
    /// <returns>
    /// sharedSecret (32 bytes): the shared secret K.
    /// ciphertext (1088 bytes): the ciphertext c to send to the decapsulator.
    /// </returns>
    public static (byte[] sharedSecret, byte[] ciphertext) Encaps(byte[] encapsulationKey)
    {
        if (encapsulationKey == null || encapsulationKey.Length != EkSize)
            throw new TlsException(AlertDescription.IllegalParameter,
                $"ML-KEM-768 encapsulation key must be {EkSize} bytes");

        byte[] m = RandomNumberGenerator.GetBytes(32);
        return EncapsInternal(encapsulationKey, m);
    }

    /// <summary>
    /// Decapsulate a ciphertext using the decapsulation key to recover the shared secret.
    /// Uses implicit rejection: returns a pseudorandom value on failure rather than an error.
    /// </summary>
    /// <param name="decapsulationKey">2400-byte decapsulation key from KeyGen.</param>
    /// <param name="ciphertext">1088-byte ciphertext from Encaps.</param>
    /// <returns>The 32-byte shared secret.</returns>
    public static byte[] Decaps(byte[] decapsulationKey, byte[] ciphertext)
    {
        if (decapsulationKey == null || decapsulationKey.Length != DkSize)
            throw new TlsException(AlertDescription.IllegalParameter,
                $"ML-KEM-768 decapsulation key must be {DkSize} bytes");
        if (ciphertext == null || ciphertext.Length != CiphertextSize)
            throw new TlsException(AlertDescription.IllegalParameter,
                $"ML-KEM-768 ciphertext must be {CiphertextSize} bytes");

        // Parse dk = encode(s_hat) || ek || H(ek) || z
        int offset = 0;
        short[][] sHat = new short[K][];
        for (int i = 0; i < K; i++)
        {
            sHat[i] = ByteDecode12(decapsulationKey, offset);
            offset += PolyBytes;
        }

        byte[] ek = new byte[EkSize];
        Buffer.BlockCopy(decapsulationKey, offset, ek, 0, EkSize);
        offset += EkSize;

        byte[] h = new byte[32];
        Buffer.BlockCopy(decapsulationKey, offset, h, 0, 32);
        offset += 32;

        byte[] z = new byte[32];
        Buffer.BlockCopy(decapsulationKey, offset, z, 0, 32);

        // m' = Decrypt(s_hat, c)
        byte[] mPrime = Decrypt(sHat, ciphertext);

        // (K', r') = G(m' || h)
        byte[] gInput = Concat(mPrime, h);
        byte[] gOutput = HashG(gInput);
        byte[] kPrime = gOutput[..32];
        byte[] rPrime = gOutput[32..];

        // c' = Encrypt(ek, m', r')
        byte[] cPrime = Encrypt(ek, mPrime, rPrime);

        // Constant-time comparison: if c == c' return K' else return J(z || c)
        int diff = ConstantTimeCompare(ciphertext, cPrime);

        // J = SHAKE-256(z || c, 32) for implicit rejection
        byte[] jInput = Concat(z, ciphertext);
        byte[] jResult = Shake256Hash(jInput, 32);

        // Select K' if match, jResult if mismatch (constant time)
        // Convert diff (0 if equal, nonzero if different) to a full byte mask
        // First collapse to 0 or 1: ((diff | -diff) >>> 31) gives 1 if nonzero, 0 if zero
        int flag = (int)(((uint)(diff | -diff)) >> 31); // 0 if equal, 1 if different
        byte mask = (byte)(-flag); // 0x00 if equal, 0xFF if different
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++)
            result[i] = (byte)((kPrime[i] & ~mask) | (jResult[i] & mask));

        return result;
    }

    // ============================================================
    // Internal key generation (deterministic, for testing)
    // ============================================================

    private static (byte[] ek, byte[] dk) KeyGenInternal(byte[] d, byte[] z)
    {
        // (rho, sigma) = G(d || k) where k = K = 3
        byte[] gInput = new byte[33];
        Buffer.BlockCopy(d, 0, gInput, 0, 32);
        gInput[32] = (byte)K;
        byte[] gOutput = HashG(gInput);
        byte[] rho = gOutput[..32];
        byte[] sigma = gOutput[32..];

        // A_hat = ExpandA(rho) -- generate matrix in NTT domain
        short[][][] aHat = new short[K][][];
        for (int i = 0; i < K; i++)
        {
            aHat[i] = new short[K][];
            for (int j = 0; j < K; j++)
                aHat[i][j] = SampleNtt(rho, (byte)j, (byte)i);
        }

        // Sample secret vector s and error vector e
        byte counter = 0;
        short[][] s = new short[K][];
        for (int i = 0; i < K; i++)
            s[i] = SampleCbd(sigma, counter++, Eta1);

        short[][] e = new short[K][];
        for (int i = 0; i < K; i++)
            e[i] = SampleCbd(sigma, counter++, Eta2);

        // Transform to NTT domain
        short[][] sHat = new short[K][];
        short[][] eHat = new short[K][];
        for (int i = 0; i < K; i++)
        {
            sHat[i] = Ntt(s[i]);
            eHat[i] = Ntt(e[i]);
        }

        // t_hat = A_hat * s_hat + e_hat
        short[][] tHat = new short[K][];
        for (int i = 0; i < K; i++)
        {
            tHat[i] = new short[N];
            for (int j = 0; j < K; j++)
            {
                short[] product = NttMultiply(aHat[i][j], sHat[j]);
                for (int c = 0; c < N; c++)
                    tHat[i][c] = (short)((tHat[i][c] + product[c]) % Q);
            }
            for (int c = 0; c < N; c++)
                tHat[i][c] = (short)((tHat[i][c] + eHat[i][c]) % Q);
        }

        // ek = encode(t_hat) || rho
        byte[] ek = new byte[EkSize];
        int offset = 0;
        for (int i = 0; i < K; i++)
        {
            ByteEncode12(tHat[i], ek, offset);
            offset += PolyBytes;
        }
        Buffer.BlockCopy(rho, 0, ek, offset, 32);

        // dk = encode(s_hat) || ek || H(ek) || z
        byte[] dk = new byte[DkSize];
        offset = 0;
        for (int i = 0; i < K; i++)
        {
            ByteEncode12(sHat[i], dk, offset);
            offset += PolyBytes;
        }
        Buffer.BlockCopy(ek, 0, dk, offset, EkSize);
        offset += EkSize;
        byte[] hEk = HashH(ek);
        Buffer.BlockCopy(hEk, 0, dk, offset, 32);
        offset += 32;
        Buffer.BlockCopy(z, 0, dk, offset, 32);

        return (ek, dk);
    }

    // ============================================================
    // Internal encapsulation (deterministic, for testing)
    // ============================================================

    private static (byte[] sharedSecret, byte[] ciphertext) EncapsInternal(byte[] ek, byte[] m)
    {
        // (K, r) = G(m || H(ek))
        byte[] hEk = HashH(ek);
        byte[] gInput = Concat(m, hEk);
        byte[] gOutput = HashG(gInput);
        byte[] sharedSecret = gOutput[..32];
        byte[] r = gOutput[32..];

        // c = Encrypt(ek, m, r)
        byte[] ciphertext = Encrypt(ek, m, r);

        return (sharedSecret, ciphertext);
    }

    // ============================================================
    // Encrypt (K-PKE.Encrypt)
    // ============================================================

    private static byte[] Encrypt(byte[] ek, byte[] m, byte[] randomness)
    {
        // Parse ek into t_hat and rho
        int offset = 0;
        short[][] tHat = new short[K][];
        for (int i = 0; i < K; i++)
        {
            tHat[i] = ByteDecode12(ek, offset);
            offset += PolyBytes;
        }
        byte[] rho = new byte[32];
        Buffer.BlockCopy(ek, offset, rho, 0, 32);

        // A_hat = ExpandA(rho) -- transpose for encryption
        short[][][] aHat = new short[K][][];
        for (int i = 0; i < K; i++)
        {
            aHat[i] = new short[K][];
            for (int j = 0; j < K; j++)
                aHat[i][j] = SampleNtt(rho, (byte)j, (byte)i);
        }

        // Sample r_vec, e1, e2 from randomness
        byte counter = 0;
        short[][] rVec = new short[K][];
        for (int i = 0; i < K; i++)
            rVec[i] = SampleCbd(randomness, counter++, Eta1);

        short[][] e1 = new short[K][];
        for (int i = 0; i < K; i++)
            e1[i] = SampleCbd(randomness, counter++, Eta2);

        short[] e2 = SampleCbd(randomness, counter, Eta2);

        // r_hat = NTT(r_vec)
        short[][] rHat = new short[K][];
        for (int i = 0; i < K; i++)
            rHat[i] = Ntt(rVec[i]);

        // u = InvNTT(A^T * r_hat) + e1
        short[][] u = new short[K][];
        for (int i = 0; i < K; i++)
        {
            short[] acc = new short[N];
            for (int j = 0; j < K; j++)
            {
                // A^T[i][j] = A[j][i]
                short[] product = NttMultiply(aHat[j][i], rHat[j]);
                for (int c = 0; c < N; c++)
                    acc[c] = (short)((acc[c] + product[c]) % Q);
            }
            u[i] = InvNtt(acc);
            for (int c = 0; c < N; c++)
                u[i][c] = (short)((u[i][c] + e1[i][c]) % Q);
        }

        // v = InvNTT(t_hat^T * r_hat) + e2 + Decompress(Decode(m, 1), 1)
        short[] vAcc = new short[N];
        for (int j = 0; j < K; j++)
        {
            short[] product = NttMultiply(tHat[j], rHat[j]);
            for (int c = 0; c < N; c++)
                vAcc[c] = (short)((vAcc[c] + product[c]) % Q);
        }
        short[] v = InvNtt(vAcc);

        // Decode m as 1-bit polynomial, then Decompress with d=1
        short[] mPoly = ByteDecode(m, 1);
        for (int c = 0; c < N; c++)
        {
            short decompressed = Decompress(mPoly[c], 1);
            v[c] = (short)((v[c] + e2[c] + decompressed) % Q);
        }

        // c1 = ByteEncode(Compress(u, du), du), c2 = ByteEncode(Compress(v, dv), dv)
        byte[] ciphertext = new byte[CiphertextSize];
        offset = 0;
        for (int i = 0; i < K; i++)
        {
            short[] compressed = CompressPoly(u[i], Du);
            ByteEncode(compressed, Du, ciphertext, offset);
            offset += CompressedPolyDu;
        }
        {
            short[] compressed = CompressPoly(v, Dv);
            ByteEncode(compressed, Dv, ciphertext, offset);
        }

        return ciphertext;
    }

    // ============================================================
    // Decrypt (K-PKE.Decrypt)
    // ============================================================

    private static byte[] Decrypt(short[][] sHat, byte[] ciphertext)
    {
        // Parse ciphertext into u (compressed) and v (compressed)
        int offset = 0;
        short[][] u = new short[K][];
        for (int i = 0; i < K; i++)
        {
            short[] compressed = ByteDecode(ciphertext, offset, Du, CompressedPolyDu);
            u[i] = DecompressPoly(compressed, Du);
            offset += CompressedPolyDu;
        }

        short[] vCompressed = ByteDecode(ciphertext, offset, Dv, CompressedPolyDv);
        short[] v = DecompressPoly(vCompressed, Dv);

        // w = v - InvNTT(s_hat^T * NTT(u))
        short[] acc = new short[N];
        for (int j = 0; j < K; j++)
        {
            short[] uHat = Ntt(u[j]);
            short[] product = NttMultiply(sHat[j], uHat);
            for (int c = 0; c < N; c++)
                acc[c] = (short)((acc[c] + product[c]) % Q);
        }
        short[] sTransU = InvNtt(acc);

        short[] w = new short[N];
        for (int c = 0; c < N; c++)
        {
            int diff = v[c] - sTransU[c];
            w[c] = (short)((diff % Q + Q) % Q);
        }

        // m = Compress(w, 1)
        short[] mPoly = CompressPoly(w, 1);
        return ByteEncode1(mPoly);
    }

    // ============================================================
    // NTT (Number Theoretic Transform)
    // ============================================================

    private static short[] PrecomputeZetas()
    {
        // zeta = 17, primitive 256th root of unity mod 3329
        short[] z = new short[128];
        z[0] = 1;

        // Compute powers of 17 mod q in bit-reversed order
        // First compute all powers: zeta^0, zeta^1, ..., zeta^127
        int[] powers = new int[128];
        powers[0] = 1;
        for (int i = 1; i < 128; i++)
            powers[i] = (int)((long)powers[i - 1] * 17 % Q);

        // Store in bit-reversed order for 7-bit indices
        for (int i = 0; i < 128; i++)
        {
            int br = BitRev7(i);
            z[i] = (short)powers[br];
        }

        return z;
    }

    private static int BitRev7(int x)
    {
        // Reverse the lower 7 bits
        int result = 0;
        for (int i = 0; i < 7; i++)
        {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        return result;
    }

    /// <summary>Forward NTT. Transforms a polynomial from normal to NTT domain.</summary>
    private static short[] Ntt(short[] f)
    {
        short[] fHat = (short[])f.Clone();
        int zetaIdx = 1;
        for (int len = 128; len >= 2; len >>= 1)
        {
            for (int start = 0; start < N; start += 2 * len)
            {
                short zeta = Zetas[zetaIdx++];
                for (int j = start; j < start + len; j++)
                {
                    short t = ModMul(zeta, fHat[j + len]);
                    fHat[j + len] = (short)((fHat[j] - t + Q) % Q);
                    fHat[j] = (short)((fHat[j] + t) % Q);
                }
            }
        }
        return fHat;
    }

    /// <summary>Inverse NTT. Transforms from NTT domain back to normal domain.</summary>
    private static short[] InvNtt(short[] fHat)
    {
        short[] f = (short[])fHat.Clone();
        int zetaIdx = 127;
        for (int len = 2; len <= 128; len <<= 1)
        {
            for (int start = 0; start < N; start += 2 * len)
            {
                short zeta = Zetas[zetaIdx--];
                for (int j = start; j < start + len; j++)
                {
                    short t = f[j];
                    f[j] = (short)((t + f[j + len]) % Q);
                    long tmp = (long)zeta * ((f[j + len] - t + Q) % Q) % Q;
                    if (tmp < 0) tmp += Q;
                    f[j + len] = (short)tmp;
                }
            }
        }

        // Multiply by 128^{-1} mod q (7-layer NTT, divisor is 2^7 = 128, not 256).
        // Extended GCD: 3329 = 26*128 + 1, so 1 = 3329 - 26*128, thus 128^{-1} = -26 = 3303 mod 3329.
        // Verify: 128 * 3303 = 422784, 422784 mod 3329 = 1.
        const int nInv = 3303;
        for (int i = 0; i < N; i++)
        {
            long tmp = (long)f[i] * nInv % Q;
            if (tmp < 0) tmp += Q;
            f[i] = (short)tmp;
        }

        return f;
    }

    /// <summary>
    /// Pointwise multiplication of two NTT-domain polynomials.
    /// In the NTT domain for Kyber, multiplication is done on pairs of coefficients
    /// (basemul), one pair per leaf of the NTT tree.
    /// </summary>
    private static short[] NttMultiply(short[] a, short[] b)
    {
        short[] c = new short[N];
        for (int i = 0; i < 64; i++)
        {
            // Each basemul operates on a pair of coefficients
            int idx = 4 * i;
            short zeta = Zetas[64 + i];

            // First pair in the block
            BaseMul(a, b, c, idx, zeta);
            // Second pair: use -zeta
            BaseMul(a, b, c, idx + 2, (short)((Q - zeta) % Q));
        }
        return c;
    }

    /// <summary>
    /// Base case multiplication for two degree-1 polynomials modulo (X^2 - zeta).
    /// (a0 + a1*X) * (b0 + b1*X) mod (X^2 - zeta)
    /// = (a0*b0 + a1*b1*zeta) + (a0*b1 + a1*b0)*X
    /// </summary>
    private static void BaseMul(short[] a, short[] b, short[] c, int idx, short zeta)
    {
        long a0 = a[idx], a1 = a[idx + 1];
        long b0 = b[idx], b1 = b[idx + 1];

        // r0 = a0*b0 + a1*b1*zeta  (mod q)
        long r0 = (a0 * b0 + (a1 * b1 % Q) * zeta) % Q;
        if (r0 < 0) r0 += Q;
        c[idx] = (short)r0;

        // r1 = a0*b1 + a1*b0  (mod q)
        long r1 = (a0 * b1 + a1 * b0) % Q;
        if (r1 < 0) r1 += Q;
        c[idx + 1] = (short)r1;
    }

    /// <summary>Modular multiplication: (a * b) mod q, result in [0, q-1].</summary>
    private static short ModMul(short a, short b)
    {
        long r = (long)a * b % Q;
        if (r < 0) r += Q;
        return (short)r;
    }

    // ============================================================
    // CBD (Centered Binomial Distribution) Sampling
    // ============================================================

    /// <summary>
    /// Sample a polynomial from the centered binomial distribution CBD_eta.
    /// Uses PRF (SHAKE-256) to expand the seed.
    /// </summary>
    private static short[] SampleCbd(byte[] seed, byte nonce, int eta)
    {
        int prf_len = 64 * eta; // Number of bytes needed: 64*eta
        byte[] prfInput = new byte[33];
        Buffer.BlockCopy(seed, 0, prfInput, 0, 32);
        prfInput[32] = nonce;

        byte[] buf = Shake256Hash(prfInput, prf_len);
        return Cbd(buf, eta);
    }

    /// <summary>
    /// CBD_eta: Centered Binomial Distribution from a byte array.
    /// FIPS 203 Algorithm 8. For eta=2: uses 4*eta = 8 bits per coefficient pair,
    /// consuming 64*eta = 128 bytes total.
    /// </summary>
    private static short[] Cbd(byte[] buf, int eta)
    {
        short[] poly = new short[N];

        if (eta == 2)
        {
            // Process 4 bytes at a time to produce 8 coefficients.
            // Each coefficient uses 2*eta = 4 bits: 2 bits for a-sum, 2 bits for b-sum.
            for (int i = 0; i < N / 8; i++)
            {
                uint t = (uint)buf[4 * i]
                       | ((uint)buf[4 * i + 1] << 8)
                       | ((uint)buf[4 * i + 2] << 16)
                       | ((uint)buf[4 * i + 3] << 24);

                // Count bits in pairs: popcount of each 2-bit group
                uint d = t & 0x55555555;
                d += (t >> 1) & 0x55555555;
                // d now holds 16 x 2-bit values, each in [0,2]

                for (int j = 0; j < 8; j++)
                {
                    int a = (int)((d >> (4 * j)) & 0x3);       // bits [4j+1:4j]
                    int b = (int)((d >> (4 * j + 2)) & 0x3);   // bits [4j+3:4j+2]
                    poly[8 * i + j] = (short)((a - b + Q) % Q);
                }
            }
        }
        else if (eta == 3)
        {
            // eta=3: 6 bits per coefficient (3+3), 3 bytes per 4 coefficients
            for (int i = 0; i < N / 4; i++)
            {
                uint t = (uint)buf[3 * i]
                       | ((uint)buf[3 * i + 1] << 8)
                       | ((uint)buf[3 * i + 2] << 16);

                uint d = t & 0x00249249;
                d += (t >> 1) & 0x00249249;
                d += (t >> 2) & 0x00249249;

                for (int j = 0; j < 4; j++)
                {
                    int a = (int)((d >> (6 * j)) & 0x7);
                    int b = (int)((d >> (6 * j + 3)) & 0x7);
                    poly[4 * i + j] = (short)((a - b + Q) % Q);
                }
            }
        }

        return poly;
    }

    // ============================================================
    // Matrix/Vector Sampling via XOF (SHAKE-128)
    // ============================================================

    /// <summary>
    /// SampleNTT: Parse a uniformly random NTT-domain polynomial from XOF output.
    /// XOF = SHAKE-128(rho || j || i), rejection sampling to get coefficients in [0, q-1].
    /// </summary>
    private static short[] SampleNtt(byte[] rho, byte j, byte i)
    {
        byte[] xofInput = new byte[34];
        Buffer.BlockCopy(rho, 0, xofInput, 0, 32);
        xofInput[32] = j;
        xofInput[33] = i;

        // We need to rejection-sample 256 coefficients from SHAKE-128 output.
        // Each attempt consumes 3 bytes to produce up to 2 coefficients.
        // On average we need about 256 * 1.5 * 3 / 2 ~ 576 bytes, but allocate more for safety.
        byte[] xofOutput = Shake128Hash(xofInput, 3 * 256); // generous allocation

        short[] poly = new short[N];
        int coeffs = 0;
        int pos = 0;

        while (coeffs < N)
        {
            if (pos + 3 > xofOutput.Length)
            {
                // Need more bytes (extremely unlikely for 768 bytes)
                byte[] more = Shake128Hash(xofInput, 3 * 256 * 2);
                byte[] combined = new byte[xofOutput.Length + more.Length];
                Buffer.BlockCopy(xofOutput, 0, combined, 0, xofOutput.Length);
                Buffer.BlockCopy(more, 0, combined, xofOutput.Length, more.Length);
                xofOutput = combined;
            }

            int d1 = (xofOutput[pos] | ((xofOutput[pos + 1] & 0x0F) << 8));
            int d2 = ((xofOutput[pos + 1] >> 4) | (xofOutput[pos + 2] << 4));
            pos += 3;

            if (d1 < Q && coeffs < N)
                poly[coeffs++] = (short)d1;
            if (d2 < Q && coeffs < N)
                poly[coeffs++] = (short)d2;
        }

        return poly;
    }

    // ============================================================
    // Compress / Decompress
    // ============================================================

    /// <summary>
    /// Compress_d(x) = Round(2^d / q * x) mod 2^d
    /// </summary>
    private static short Compress(int x, int d)
    {
        // Ensure x is in [0, q-1]
        x = ((x % Q) + Q) % Q;
        // round((2^d * x) / q) mod 2^d
        long numerator = ((long)x << d) + (Q / 2); // + q/2 for rounding
        int result = (int)(numerator / Q);
        return (short)(result & ((1 << d) - 1));
    }

    /// <summary>
    /// Decompress_d(x) = Round(q / 2^d * x)
    /// </summary>
    private static short Decompress(int x, int d)
    {
        // round(q * x / 2^d)
        long numerator = (long)Q * x + (1L << (d - 1)); // + 2^(d-1) for rounding
        return (short)(numerator >> d);
    }

    private static short[] CompressPoly(short[] poly, int d)
    {
        short[] result = new short[N];
        for (int i = 0; i < N; i++)
            result[i] = Compress(poly[i], d);
        return result;
    }

    private static short[] DecompressPoly(short[] poly, int d)
    {
        short[] result = new short[N];
        for (int i = 0; i < N; i++)
            result[i] = Decompress(poly[i], d);
        return result;
    }

    // ============================================================
    // Byte Encoding / Decoding
    // ============================================================

    /// <summary>
    /// ByteEncode_12: Pack a polynomial with 12-bit coefficients into bytes.
    /// Each pair of coefficients (a, b) maps to 3 bytes.
    /// </summary>
    private static void ByteEncode12(short[] poly, byte[] output, int offset)
    {
        for (int i = 0; i < N / 2; i++)
        {
            int a = poly[2 * i] & 0xFFF;
            int b = poly[2 * i + 1] & 0xFFF;
            output[offset + 3 * i] = (byte)(a & 0xFF);
            output[offset + 3 * i + 1] = (byte)((a >> 8) | ((b & 0xF) << 4));
            output[offset + 3 * i + 2] = (byte)(b >> 4);
        }
    }

    /// <summary>
    /// ByteDecode_12: Unpack 12-bit coefficients from bytes.
    /// </summary>
    private static short[] ByteDecode12(byte[] input, int offset)
    {
        short[] poly = new short[N];
        for (int i = 0; i < N / 2; i++)
        {
            int b0 = input[offset + 3 * i] & 0xFF;
            int b1 = input[offset + 3 * i + 1] & 0xFF;
            int b2 = input[offset + 3 * i + 2] & 0xFF;
            poly[2 * i] = (short)(b0 | ((b1 & 0x0F) << 8));
            poly[2 * i + 1] = (short)((b1 >> 4) | (b2 << 4));
        }
        return poly;
    }

    /// <summary>
    /// ByteEncode_d: Pack d-bit coefficients into a byte array.
    /// </summary>
    private static void ByteEncode(short[] poly, int d, byte[] output, int offset)
    {
        if (d == 12)
        {
            ByteEncode12(poly, output, offset);
            return;
        }

        // Generic bit-packing
        int bitPos = 0;
        for (int i = 0; i < N; i++)
        {
            int val = poly[i] & ((1 << d) - 1);
            for (int bit = 0; bit < d; bit++)
            {
                int byteIdx = offset + (bitPos >> 3);
                int bitIdx = bitPos & 7;
                output[byteIdx] |= (byte)(((val >> bit) & 1) << bitIdx);
                bitPos++;
            }
        }
    }

    /// <summary>
    /// ByteDecode_d: Unpack d-bit coefficients from a byte array.
    /// </summary>
    private static short[] ByteDecode(byte[] input, int d)
    {
        return ByteDecode(input, 0, d, N * d / 8);
    }

    private static short[] ByteDecode(byte[] input, int offset, int d, int byteLen)
    {
        if (d == 12)
            return ByteDecode12(input, offset);

        short[] poly = new short[N];
        int bitPos = 0;
        for (int i = 0; i < N; i++)
        {
            int val = 0;
            for (int bit = 0; bit < d; bit++)
            {
                int byteIdx = offset + (bitPos >> 3);
                int bitIdx = bitPos & 7;
                val |= ((input[byteIdx] >> bitIdx) & 1) << bit;
                bitPos++;
            }
            poly[i] = (short)val;
        }
        return poly;
    }

    /// <summary>
    /// ByteEncode_1: Pack single-bit polynomial (compression d=1) into 32 bytes.
    /// </summary>
    private static byte[] ByteEncode1(short[] poly)
    {
        byte[] output = new byte[32];
        for (int i = 0; i < N; i++)
        {
            if ((poly[i] & 1) != 0)
                output[i >> 3] |= (byte)(1 << (i & 7));
        }
        return output;
    }

    // ============================================================
    // Hash Functions
    // ============================================================

    /// <summary>H = SHA3-256</summary>
    private static byte[] HashH(byte[] input) => Keccak.Sha3_256(input);

    /// <summary>G = SHA3-512 (produces 64 bytes, split into two 32-byte halves)</summary>
    private static byte[] HashG(byte[] input) => Keccak.Sha3_512(input);

    /// <summary>J = SHAKE-256(input, outputLen)</summary>
    private static byte[] Shake256Hash(byte[] input, int outputLen) => Keccak.Shake256(input, outputLen);

    /// <summary>XOF = SHAKE-128(input, outputLen)</summary>
    private static byte[] Shake128Hash(byte[] input, int outputLen) => Keccak.Shake128(input, outputLen);

    // ============================================================
    // Utility
    // ============================================================

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    /// <summary>
    /// Constant-time comparison of two byte arrays.
    /// Returns 0 if equal, nonzero if different.
    /// </summary>
    private static int ConstantTimeCompare(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return 1;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff;
    }
}
