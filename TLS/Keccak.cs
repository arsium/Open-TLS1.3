namespace TLS;

/// <summary>
/// Pure managed Keccak-f[1600] sponge construction implementing SHA3-256, SHA3-512,
/// SHAKE-128, and SHAKE-256. No OS crypto provider dependency — works on all platforms.
/// </summary>
internal static class Keccak
{
    private const int StateSize = 25; // 5x5 lanes of 64 bits = 1600 bits

    // Round constants for Keccak-f[1600]
    private static readonly ulong[] RC =
    {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

    // Rotation offsets for rho step
    private static readonly int[] RhoOffsets =
    {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    };

    // Pi step permutation indices
    private static readonly int[] PiIndices =
    {
         0, 10, 20,  5, 15,
        16,  1, 11, 21,  6,
         7, 17,  2, 12, 22,
        23,  8, 18,  3, 13,
        14, 24,  9, 19,  4,
    };

    /// <summary>SHA3-256: 32-byte hash.</summary>
    public static byte[] Sha3_256(byte[] input)
    {
        return SpongeHash(input, 136, 32, 0x06); // rate=136 (1088 bits), capacity=512 bits
    }

    /// <summary>SHA3-512: 64-byte hash.</summary>
    public static byte[] Sha3_512(byte[] input)
    {
        return SpongeHash(input, 72, 64, 0x06); // rate=72 (576 bits), capacity=1024 bits
    }

    /// <summary>SHAKE-128: arbitrary-length XOF output.</summary>
    public static byte[] Shake128(byte[] input, int outputLen)
    {
        return SpongeHash(input, 168, outputLen, 0x1F); // rate=168 (1344 bits)
    }

    /// <summary>SHAKE-256: arbitrary-length XOF output.</summary>
    public static byte[] Shake256(byte[] input, int outputLen)
    {
        return SpongeHash(input, 136, outputLen, 0x1F); // rate=136 (1088 bits)
    }

    private static byte[] SpongeHash(byte[] input, int rateBytes, int outputLen, byte domainSep)
    {
        ulong[] state = new ulong[StateSize];

        // Absorb phase: XOR input blocks into state and permute
        int offset = 0;
        int rateLanes = rateBytes / 8;

        while (offset + rateBytes <= input.Length)
        {
            for (int i = 0; i < rateLanes; i++)
                state[i] ^= ReadLittleEndian64(input, offset + i * 8);
            KeccakF1600(state);
            offset += rateBytes;
        }

        // Pad the final block: input remainder + domain separation + 10*1 padding
        byte[] padded = new byte[rateBytes];
        int remaining = input.Length - offset;
        Buffer.BlockCopy(input, offset, padded, 0, remaining);
        padded[remaining] = domainSep;
        padded[rateBytes - 1] |= 0x80;

        for (int i = 0; i < rateLanes; i++)
            state[i] ^= ReadLittleEndian64(padded, i * 8);
        KeccakF1600(state);

        // Squeeze phase
        byte[] output = new byte[outputLen];
        int outOffset = 0;

        while (outOffset < outputLen)
        {
            int toCopy = Math.Min(rateBytes, outputLen - outOffset);
            for (int i = 0; i < (toCopy + 7) / 8; i++)
            {
                int bytes = Math.Min(8, toCopy - i * 8);
                WriteLittleEndian64(output, outOffset + i * 8, state[i], bytes);
            }
            outOffset += toCopy;
            if (outOffset < outputLen)
                KeccakF1600(state);
        }

        return output;
    }

    /// <summary>Keccak-f[1600] permutation — 24 rounds.</summary>
    private static void KeccakF1600(ulong[] state)
    {
        ulong[] C = new ulong[5];
        ulong[] temp = new ulong[StateSize];

        for (int round = 0; round < 24; round++)
        {
            // Theta
            for (int x = 0; x < 5; x++)
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

            for (int x = 0; x < 5; x++)
            {
                ulong d = C[(x + 4) % 5] ^ RotL(C[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5)
                    state[y + x] ^= d;
            }

            // Rho + Pi (combined)
            for (int i = 0; i < StateSize; i++)
                temp[PiIndices[i]] = RotL(state[i], RhoOffsets[i]);

            // Chi
            for (int y = 0; y < 25; y += 5)
            {
                for (int x = 0; x < 5; x++)
                    state[y + x] = temp[y + x] ^ (~temp[y + (x + 1) % 5] & temp[y + (x + 2) % 5]);
            }

            // Iota
            state[0] ^= RC[round];
        }
    }

    private static ulong RotL(ulong x, int n) => (x << n) | (x >> (64 - n));

    private static ulong ReadLittleEndian64(byte[] buf, int offset)
    {
        return (ulong)buf[offset]
             | (ulong)buf[offset + 1] << 8
             | (ulong)buf[offset + 2] << 16
             | (ulong)buf[offset + 3] << 24
             | (ulong)buf[offset + 4] << 32
             | (ulong)buf[offset + 5] << 40
             | (ulong)buf[offset + 6] << 48
             | (ulong)buf[offset + 7] << 56;
    }

    private static void WriteLittleEndian64(byte[] buf, int offset, ulong value, int bytes)
    {
        for (int i = 0; i < bytes; i++)
        {
            buf[offset + i] = (byte)(value >> (i * 8));
        }
    }
}
