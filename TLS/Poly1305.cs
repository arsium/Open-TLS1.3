namespace TLS;

using System.Buffers.Binary;

/// <summary>
/// RFC 8439 Poly1305 one-time authenticator.
///
/// Implementation strategy (RFC 8439 §2.5.1 + Bernstein's reference):
/// the prime is p = 2^130 - 5. Represent the 130-bit accumulator as five
/// 26-bit limbs in 64-bit registers so each multiply-and-add fits without
/// overflow before the carry-propagation pass. r is clamped per §2.5.
/// </summary>
internal static class Poly1305
{
    public const int TagSize = 16;
    public const int KeySize = 32;

    /// <summary>
    /// Compute the 16-byte Poly1305 tag of <paramref name="data"/> under the 32-byte one-time key.
    /// The first 16 bytes of the key are r (clamped), the last 16 are s (added before serialization).
    /// </summary>
    public static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        if (key.Length != KeySize) throw new ArgumentException("Poly1305 key must be 32 bytes", nameof(key));
        if (tag.Length < TagSize) throw new ArgumentException("Tag buffer too small", nameof(tag));

        // r = key[0..16] with the clamp from RFC 8439 §2.5:
        //   clear top 4 bits of bytes 3, 7, 11, 15
        //   clear bottom 2 bits of bytes 4, 8, 12
        uint r0 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice( 0, 4))     ) & 0x03FFFFFF;
        uint r1 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice( 3, 4)) >> 2) & 0x03FFFF03;
        uint r2 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice( 6, 4)) >> 4) & 0x03FFC0FF;
        uint r3 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice( 9, 4)) >> 6) & 0x03F03FFF;
        uint r4 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4)) >> 8) & 0x000FFFFF;

        // Pre-multiplied by 5: needed for the (a * r) mod (2^130 - 5) reduction step.
        uint s1 = r1 * 5;
        uint s2 = r2 * 5;
        uint s3 = r3 * 5;
        uint s4 = r4 * 5;

        // Accumulator, five 26-bit limbs.
        ulong h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

        Span<byte> block = stackalloc byte[16];
        int offset = 0;
        while (offset < data.Length)
        {
            int blkLen = Math.Min(16, data.Length - offset);
            // Pad incomplete final block with zeros and apply the implicit
            // "0x01" hi bit at position 8*blkLen rather than at bit 128.
            if (blkLen == 16)
            {
                LoadBlock16(data.Slice(offset, 16), out uint b0, out uint b1, out uint b2, out uint b3, out uint b4Hi);
                // Add to accumulator with the high "1" bit set above the block.
                h0 += b0;
                h1 += b1;
                h2 += b2;
                h3 += b3;
                h4 += b4Hi | (1u << 24); // (1 << 128) in the limb decomposition
            }
            else
            {
                block.Clear();
                data.Slice(offset, blkLen).CopyTo(block);
                block[blkLen] = 0x01; // implicit hi bit at the byte just past the message
                LoadBlock16(block, out uint b0, out uint b1, out uint b2, out uint b3, out uint b4Hi);
                h0 += b0;
                h1 += b1;
                h2 += b2;
                h3 += b3;
                h4 += b4Hi; // hi bit is already baked in via block[blkLen] = 0x01
            }

            // h *= r (mod 2^130 - 5), still in 26-bit limbs.
            ulong d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            ulong d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            ulong d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            ulong d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            ulong d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            // Carry propagation.
            ulong c;
            c  = d0 >> 26; h0 = d0 & 0x3FFFFFF;
            d1 += c; c = d1 >> 26; h1 = d1 & 0x3FFFFFF;
            d2 += c; c = d2 >> 26; h2 = d2 & 0x3FFFFFF;
            d3 += c; c = d3 >> 26; h3 = d3 & 0x3FFFFFF;
            d4 += c; c = d4 >> 26; h4 = d4 & 0x3FFFFFF;
            h0 += c * 5;
            c = h0 >> 26; h0 &= 0x3FFFFFF;
            h1 += c;

            offset += blkLen;
        }

        // Final carry pass to fully reduce.
        ulong cc;
        cc = h1 >> 26; h1 &= 0x3FFFFFF;
        h2 += cc; cc = h2 >> 26; h2 &= 0x3FFFFFF;
        h3 += cc; cc = h3 >> 26; h3 &= 0x3FFFFFF;
        h4 += cc; cc = h4 >> 26; h4 &= 0x3FFFFFF;
        h0 += cc * 5; cc = h0 >> 26; h0 &= 0x3FFFFFF;
        h1 += cc;

        // Conditional subtraction of p = 2^130 - 5 if h >= p.
        // Compute g = h + 5 then check the top bit; if it overflowed we want g, else h.
        ulong g0 = h0 + 5;
        ulong c0 = g0 >> 26; g0 &= 0x3FFFFFF;
        ulong g1 = h1 + c0; ulong c1 = g1 >> 26; g1 &= 0x3FFFFFF;
        ulong g2 = h2 + c1; ulong c2 = g2 >> 26; g2 &= 0x3FFFFFF;
        ulong g3 = h3 + c2; ulong c3 = g3 >> 26; g3 &= 0x3FFFFFF;
        ulong g4 = h4 + c3 - (1UL << 26);

        // mask = -1 if h >= p (i.e. g didn't borrow), else 0.
        ulong mask = (g4 >> 63) - 1;     // 0 if g4's borrow bit set, all-ones otherwise
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Pack the five 26-bit limbs into a 128-bit little-endian value (lo, hi). The bit
        // layout is: h0=[0..25], h1=[26..51], h2=[52..77], h3=[78..103], h4=[104..129].
        // We want h mod 2^128, so we drop bits >= 128 (the shift past 64 truncates them).
        ulong lo = h0 | (h1 << 26) | (h2 << 52);
        ulong hi = (h2 >> 12) | (h3 << 14) | (h4 << 40);

        // Add the 16-byte 's' (second half of the key) modulo 2^128.
        ulong sLo = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(16, 8));
        ulong sHi = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(24, 8));

        ulong newLo = lo + sLo;
        ulong carryAdd = newLo < lo ? 1UL : 0UL;
        ulong newHi = hi + sHi + carryAdd;

        BinaryPrimitives.WriteUInt64LittleEndian(tag.Slice(0, 8), newLo);
        BinaryPrimitives.WriteUInt64LittleEndian(tag.Slice(8, 8), newHi);
    }

    // Split a 16-byte little-endian block into five 26-bit limbs (b4Hi is only the low 24 bits;
    // caller decides whether to set the implicit 2^128 hi-bit on b4Hi).
    private static void LoadBlock16(ReadOnlySpan<byte> block,
        out uint b0, out uint b1, out uint b2, out uint b3, out uint b4Hi)
    {
        uint t0 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice( 0, 4));
        uint t1 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice( 4, 4));
        uint t2 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice( 8, 4));
        uint t3 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12, 4));

        b0 = t0 & 0x03FFFFFF;
        b1 = ((t0 >> 26) | (t1 <<  6)) & 0x03FFFFFF;
        b2 = ((t1 >> 20) | (t2 << 12)) & 0x03FFFFFF;
        b3 = ((t2 >> 14) | (t3 << 18)) & 0x03FFFFFF;
        b4Hi = (t3 >> 8) & 0x00FFFFFF; // 24 bits; caller may OR in the 1<<24 hi-bit
    }
}
