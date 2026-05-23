namespace TLS;

using System.Buffers.Binary;

/// <summary>
/// RFC 8439 (IETF ChaCha20) — pure managed implementation of the stream cipher,
/// used as a fallback when <see cref="System.Security.Cryptography.ChaCha20Poly1305"/>
/// is unavailable (e.g. older Windows where BCrypt lacks CHACHA20_POLY1305).
///
/// 256-bit key, 96-bit nonce, 32-bit block counter.
/// </summary>
internal static class ChaCha20
{
    private const uint C0 = 0x61707865; // "expa"
    private const uint C1 = 0x3320646E; // "nd 3"
    private const uint C2 = 0x79622D32; // "2-by"
    private const uint C3 = 0x6B206574; // "te k"

    /// <summary>
    /// XOR <paramref name="input"/> into <paramref name="output"/> using ChaCha20 keystream
    /// with the given 32-byte key, 12-byte nonce, and starting block counter.
    /// </summary>
    public static void XorKeystream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        uint initialCounter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (key.Length != 32) throw new ArgumentException("ChaCha20 key must be 32 bytes", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("ChaCha20 nonce must be 12 bytes", nameof(nonce));
        if (output.Length < input.Length) throw new ArgumentException("Output too short");

        Span<uint> state = stackalloc uint[16];
        InitState(state, key, nonce, initialCounter);

        Span<byte> block = stackalloc byte[64];
        int offset = 0;
        while (offset < input.Length)
        {
            BlockFunction(state, block);
            int take = Math.Min(64, input.Length - offset);
            for (int i = 0; i < take; i++)
                output[offset + i] = (byte)(input[offset + i] ^ block[i]);
            offset += take;
            state[12]++; // increment block counter
        }
    }

    /// <summary>Emit <paramref name="output"/>.Length bytes of keystream (no input XOR).</summary>
    public static void Keystream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        uint initialCounter, Span<byte> output)
    {
        if (key.Length != 32) throw new ArgumentException("ChaCha20 key must be 32 bytes", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("ChaCha20 nonce must be 12 bytes", nameof(nonce));

        Span<uint> state = stackalloc uint[16];
        InitState(state, key, nonce, initialCounter);

        Span<byte> block = stackalloc byte[64];
        int offset = 0;
        while (offset < output.Length)
        {
            BlockFunction(state, block);
            int take = Math.Min(64, output.Length - offset);
            block.Slice(0, take).CopyTo(output.Slice(offset, take));
            offset += take;
            state[12]++;
        }
    }

    private static void InitState(Span<uint> state, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce, uint counter)
    {
        state[0] = C0; state[1] = C1; state[2] = C2; state[3] = C3;
        for (int i = 0; i < 8; i++)
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        state[12] = counter;
        state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4));
        state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
        state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));
    }

    /// <summary>
    /// One ChaCha20 block: 20 rounds (10 column + 10 diagonal), serialized little-endian.
    /// </summary>
    private static void BlockFunction(ReadOnlySpan<uint> startState, Span<byte> output)
    {
        uint x0  = startState[0],  x1  = startState[1],  x2  = startState[2],  x3  = startState[3];
        uint x4  = startState[4],  x5  = startState[5],  x6  = startState[6],  x7  = startState[7];
        uint x8  = startState[8],  x9  = startState[9],  x10 = startState[10], x11 = startState[11];
        uint x12 = startState[12], x13 = startState[13], x14 = startState[14], x15 = startState[15];

        // 10 double-rounds = 20 rounds total (RFC 8439 §2.3.1)
        for (int i = 0; i < 10; i++)
        {
            // Column rounds
            QR(ref x0, ref x4,  ref x8,  ref x12);
            QR(ref x1, ref x5,  ref x9,  ref x13);
            QR(ref x2, ref x6,  ref x10, ref x14);
            QR(ref x3, ref x7,  ref x11, ref x15);
            // Diagonal rounds
            QR(ref x0, ref x5,  ref x10, ref x15);
            QR(ref x1, ref x6,  ref x11, ref x12);
            QR(ref x2, ref x7,  ref x8,  ref x13);
            QR(ref x3, ref x4,  ref x9,  ref x14);
        }

        // Add the original state and serialize little-endian.
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(0,  4), x0  + startState[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4,  4), x1  + startState[1]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(8,  4), x2  + startState[2]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(12, 4), x3  + startState[3]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(16, 4), x4  + startState[4]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(20, 4), x5  + startState[5]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(24, 4), x6  + startState[6]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(28, 4), x7  + startState[7]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(32, 4), x8  + startState[8]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(36, 4), x9  + startState[9]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(40, 4), x10 + startState[10]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(44, 4), x11 + startState[11]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(48, 4), x12 + startState[12]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(52, 4), x13 + startState[13]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(56, 4), x14 + startState[14]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(60, 4), x15 + startState[15]);
    }

    // RFC 8439 §2.1: ChaCha quarter-round
    private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d ^= a; d = Rotl(d, 16);
        c += d; b ^= c; b = Rotl(b, 12);
        a += b; d ^= a; d = Rotl(d,  8);
        c += d; b ^= c; b = Rotl(b,  7);
    }

    private static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));
}
