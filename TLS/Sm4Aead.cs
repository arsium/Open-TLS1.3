namespace TLS;

using System.Buffers.Binary;
using System.Security.Cryptography;

/// <summary>
/// SM4-GCM and SM4-CCM AEAD per RFC 8998, built on the SM4 block cipher (GB/T 32907-2016).
/// .NET's AesGcm/AesCcm are AES-only, so GCM (GHASH over the reflected GF(2^128) + SM4-CTR)
/// and CCM (CBC-MAC + CTR) are implemented generically here. 16-byte tag, 12-byte nonce.
/// </summary>
public sealed class Sm4Aead
{
    private const int Block = 16;
    private readonly uint[] _rk;     // SM4 encryption round keys
    private readonly bool _ccm;
    private readonly int _tagLen;
    private readonly ulong _hHi, _hLo; // GHASH subkey H = E(0), packed big-endian (GCM only)

    public Sm4Aead(byte[] key, bool ccm, int tagLen = 16)
    {
        _rk = ChineseCrypto.SM4.ExpandKey(key);
        _ccm = ccm;
        _tagLen = tagLen;
        if (!ccm)
        {
            byte[] h = new byte[Block];
            E(new byte[Block], h); // H = E(0^128)
            _hHi = BinaryPrimitives.ReadUInt64BigEndian(h);
            _hLo = BinaryPrimitives.ReadUInt64BigEndian(h.AsSpan(8));
        }
    }

    public int TagLength => _tagLen;

    public byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        byte[] result = new byte[plaintext.Length + _tagLen];
        EncryptInto(nonce, plaintext, result, aad);
        return result;
    }

    /// <summary>
    /// Encrypt straight into <paramref name="output"/> = ciphertext||tag. <c>output.Length</c>
    /// MUST equal <c>plaintext.Length + TagLength</c>. Matches AesGcmManaged / ChaCha20Poly1305Managed
    /// / Mgm for uniform dispatch from AeadCipher.
    /// </summary>
    public void EncryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        Span<byte> output, ReadOnlySpan<byte> aad)
    {
        if (output.Length != plaintext.Length + _tagLen)
            throw new ArgumentException($"output must be plaintext.Length + {_tagLen} bytes");
        if (_ccm) CcmEncryptInto(nonce, plaintext, output, aad);
        else      GcmEncryptInto(nonce, plaintext, output, aad);
    }

    public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0) { plaintext = null; return false; }
        byte[] pt = new byte[ctLen];
        if (TryDecryptInto(nonce, encrypted, pt, aad))
        {
            plaintext = pt;
            return true;
        }
        plaintext = null;
        return false;
    }

    /// <summary>Verify+decrypt <paramref name="ctAndTag"/> directly into <paramref name="plaintext"/>.
    /// Returns false on tag mismatch.</summary>
    public bool TryDecryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ctAndTag,
        Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        int ctLen = ctAndTag.Length - _tagLen;
        if (ctLen < 0 || plaintext.Length != ctLen) return false;
        return _ccm ? CcmTryDecryptInto(nonce, ctAndTag, plaintext, aad)
                    : GcmTryDecryptInto(nonce, ctAndTag, plaintext, aad);
    }

    public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad)
    {
        if (!TryDecrypt(nonce, encrypted, aad, out var pt))
            throw new CryptographicException("SM4 AEAD authentication tag mismatch");
        return pt!;
    }

    private void E(ReadOnlySpan<byte> input, Span<byte> output) => ChineseCrypto.SM4.EncryptBlock(_rk, input, output);

    // ---------------- GCM ----------------

    private void GcmEncryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pt,
        Span<byte> output, ReadOnlySpan<byte> aad)
    {
        // output = ct||tag. Write ciphertext directly into the output buffer's first slice;
        // no intermediate ct allocation. Tag goes in the trailing slice.
        var ctSpan = output.Slice(0, pt.Length);
        var tagSpan = output.Slice(pt.Length, _tagLen);

        byte[] j0 = GcmJ0(nonce);
        Gctr(j0, increment: true, pt, ctSpan);

        // GHash + E(J0) → tag, all working buffers stackalloc'd.
        Span<byte> s = stackalloc byte[Block];
        GHashInto(aad, ctSpan, s);
        Span<byte> ej0 = stackalloc byte[Block];
        E(j0, ej0);
        for (int i = 0; i < _tagLen; i++) tagSpan[i] = (byte)(s[i] ^ ej0[i]);
    }

    private bool GcmTryDecryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> enc,
        Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        int ctLen = enc.Length - _tagLen;
        var ct = enc[..ctLen];
        var tag = enc[ctLen..];

        byte[] j0 = GcmJ0(nonce);
        Span<byte> s = stackalloc byte[Block];
        GHashInto(aad, ct, s);
        Span<byte> ej0 = stackalloc byte[Block];
        E(j0, ej0);
        Span<byte> expected = stackalloc byte[_tagLen];
        for (int i = 0; i < _tagLen; i++) expected[i] = (byte)(s[i] ^ ej0[i]);
        if (!CryptographicOperations.FixedTimeEquals(tag, expected)) return false;

        Gctr(j0, increment: true, ct, plaintext);
        return true;
    }

    private static byte[] GcmJ0(ReadOnlySpan<byte> nonce)
    {
        // 96-bit IV path (TLS always uses a 12-byte nonce): J0 = IV || 0x00000001.
        byte[] j0 = new byte[Block];
        nonce[..12].CopyTo(j0);
        j0[15] = 1;
        return j0;
    }

    // GCTR with the counter pre-incremented before the first keystream block.
    private void Gctr(byte[] j0, bool increment, ReadOnlySpan<byte> input, Span<byte> output)
    {
        byte[] ctr = (byte[])j0.Clone();
        byte[] ks = new byte[Block];
        for (int off = 0; off < input.Length; off += Block)
        {
            Inc32(ctr);
            E(ctr, ks);
            int blk = Math.Min(Block, input.Length - off);
            for (int i = 0; i < blk; i++) output[off + i] = (byte)(input[off + i] ^ ks[i]);
        }
    }

    // Allocation-free GHash that writes the 16-byte digest into a caller-provided span.
    // The previous byte[] return was a small but per-record allocation on the GCM hot path.
    private void GHashInto(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ct, Span<byte> y)
    {
        ulong yHi = 0, yLo = 0;
        GHashBlocks(ref yHi, ref yLo, aad);
        GHashBlocks(ref yHi, ref yLo, ct);
        // length block: len(A) || len(C) in bits, big-endian
        yHi ^= (ulong)aad.Length * 8;
        yLo ^= (ulong)ct.Length * 8;
        GfMul(ref yHi, ref yLo);
        BinaryPrimitives.WriteUInt64BigEndian(y, yHi);
        BinaryPrimitives.WriteUInt64BigEndian(y.Slice(8), yLo);
    }

    private void GHashBlocks(ref ulong yHi, ref ulong yLo, ReadOnlySpan<byte> data)
    {
        // Hoisted out of the loop to satisfy CA2014. Only the trailing partial block uses tmp.
        Span<byte> tmp = stackalloc byte[Block];
        for (int off = 0; off < data.Length; off += Block)
        {
            int blk = Math.Min(Block, data.Length - off);
            ulong bHi, bLo;
            if (blk == Block)
            {
                bHi = BinaryPrimitives.ReadUInt64BigEndian(data.Slice(off));
                bLo = BinaryPrimitives.ReadUInt64BigEndian(data.Slice(off + 8));
            }
            else
            {
                tmp.Clear();
                data.Slice(off, blk).CopyTo(tmp);
                bHi = BinaryPrimitives.ReadUInt64BigEndian(tmp);
                bLo = BinaryPrimitives.ReadUInt64BigEndian(tmp.Slice(8));
            }
            yHi ^= bHi; yLo ^= bLo;
            GfMul(ref yHi, ref yLo);
        }
    }

    // GHASH GF(2^128) multiply (SP 800-38D): reflected field, R = 0xE1‖0^120.
    // X and H packed as two big-endian ulongs (hi = bytes 0..7, lo = bytes 8..15).
    private void GfMul(ref ulong xHi, ref ulong xLo)
    {
        ulong zHi = 0, zLo = 0, vHi = _hHi, vLo = _hLo;
        for (int i = 0; i < 64; i++)
        {
            if (((xHi >> (63 - i)) & 1) != 0) { zHi ^= vHi; zLo ^= vLo; }
            ulong lsb = vLo & 1;
            vLo = (vLo >> 1) | (vHi << 63); vHi >>= 1;
            if (lsb != 0) vHi ^= 0xE100000000000000UL;
        }
        for (int i = 0; i < 64; i++)
        {
            if (((xLo >> (63 - i)) & 1) != 0) { zHi ^= vHi; zLo ^= vLo; }
            ulong lsb = vLo & 1;
            vLo = (vLo >> 1) | (vHi << 63); vHi >>= 1;
            if (lsb != 0) vHi ^= 0xE100000000000000UL;
        }
        xHi = zHi; xLo = zLo;
    }

    private static void Inc32(byte[] ctr)
    {
        for (int i = 15; i >= 12; i--)
            if (++ctr[i] != 0) break;
    }

    // ---------------- CCM ----------------

    private void CcmEncryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pt,
        Span<byte> output, ReadOnlySpan<byte> aad)
    {
        var ctSpan = output.Slice(0, pt.Length);
        var tagSpan = output.Slice(pt.Length, _tagLen);

        Span<byte> tag = stackalloc byte[Block];
        CcmMacInto(nonce, pt, aad, tag);
        Span<byte> s0 = stackalloc byte[Block];
        CcmKeystream0Into(nonce, s0);
        for (int i = 0; i < _tagLen; i++) tagSpan[i] = (byte)(tag[i] ^ s0[i]);

        CcmCtr(nonce, pt, ctSpan);
    }

    private bool CcmTryDecryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> enc,
        Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        int ctLen = enc.Length - _tagLen;
        var ct = enc[..ctLen];
        var tag = enc[ctLen..];

        CcmCtr(nonce, ct, plaintext);

        Span<byte> t = stackalloc byte[Block];
        CcmMacInto(nonce, plaintext, aad, t);
        Span<byte> s0 = stackalloc byte[Block];
        CcmKeystream0Into(nonce, s0);
        Span<byte> expected = stackalloc byte[_tagLen];
        for (int i = 0; i < _tagLen; i++) expected[i] = (byte)(t[i] ^ s0[i]);
        if (!CryptographicOperations.FixedTimeEquals(tag, expected))
        {
            // Wipe partial plaintext if tag check fails.
            plaintext.Clear();
            return false;
        }
        return true;
    }

    private int L => 15 - 12; // nonce is 12 bytes ⇒ L = 3

    // Writes T (the CBC-MAC, before S0 XOR) into the caller's span. All per-call working
    // buffers are now stackalloc'd or reused across loop iterations — previously each
    // CCM call did ~1024 per-block byte[Block] allocations in CbcMacBlocks alone.
    private void CcmMacInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pt,
        ReadOnlySpan<byte> aad, Span<byte> t)
    {
        // B0 = flags || nonce || Q
        Span<byte> b0 = stackalloc byte[Block];
        int mPrime = (_tagLen - 2) / 2;
        b0[0] = (byte)((aad.Length > 0 ? 0x40 : 0) | (mPrime << 3) | (L - 1));
        nonce[..12].CopyTo(b0.Slice(1));
        WriteBE(b0.Slice(1 + 12), (uint)pt.Length, L);

        E(b0, t); // T = E(B0)

        if (aad.Length > 0)
        {
            // associated data: 2-byte BE length prefix (for len < 2^16-2^8), then aad, zero-padded
            // Pool the framed AAD buffer — it's len(2) + aad.Length bytes (TLS AAD is 5 B,
            // so this is tiny in practice but per-record on the bulk path).
            int encLen = 2 + aad.Length;
            byte[] encArr = System.Buffers.ArrayPool<byte>.Shared.Rent(encLen);
            try
            {
                var enc = encArr.AsSpan(0, encLen);
                BinaryPrimitives.WriteUInt16BigEndian(enc, (ushort)aad.Length);
                aad.CopyTo(enc.Slice(2));
                CbcMacBlocks(t, enc);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encArr.AsSpan(0, encLen));
                System.Buffers.ArrayPool<byte>.Shared.Return(encArr);
            }
        }
        CbcMacBlocks(t, pt);
    }

    private void CbcMacBlocks(Span<byte> t, ReadOnlySpan<byte> data)
    {
        // Pre-allocate the block + cipher-output buffers ONCE per call instead of
        // per-iteration (was ~1024 allocations on a 16 KB record).
        Span<byte> block = stackalloc byte[Block];
        Span<byte> o = stackalloc byte[Block];
        for (int off = 0; off < data.Length; off += Block)
        {
            int blk = Math.Min(Block, data.Length - off);
            block.Clear();
            data.Slice(off, blk).CopyTo(block);
            XorBlockSpan(t, block);
            E(t, o);
            o.CopyTo(t);
        }
    }

    private void CcmKeystream0Into(ReadOnlySpan<byte> nonce, Span<byte> s0)
    {
        Span<byte> a0 = stackalloc byte[Block];
        CcmCtrBlockInto(nonce, 0, a0);
        E(a0, s0);
    }

    private void CcmCtr(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
    {
        // ks + a are reused across all iterations; was ~1024 byte[Block] allocations
        // (the per-iter CcmCtrBlock) on a 16 KB record. Big drop in GC pressure.
        Span<byte> ks = stackalloc byte[Block];
        Span<byte> a = stackalloc byte[Block];
        // The flags+nonce prefix doesn't change between counter values — write once.
        a[0] = (byte)(L - 1);
        nonce[..12].CopyTo(a.Slice(1));
        int counter = 1;
        for (int off = 0; off < input.Length; off += Block, counter++)
        {
            WriteBE(a.Slice(1 + 12), (uint)counter, L);
            E(a, ks);
            int blk = Math.Min(Block, input.Length - off);
            for (int i = 0; i < blk; i++) output[off + i] = (byte)(input[off + i] ^ ks[i]);
        }
    }

    private void CcmCtrBlockInto(ReadOnlySpan<byte> nonce, uint counter, Span<byte> a)
    {
        a[0] = (byte)(L - 1);
        nonce[..12].CopyTo(a.Slice(1));
        WriteBE(a.Slice(1 + 12), counter, L);
    }

    // Span-typed sibling of XorBlock for callers that work in stackalloc spans.
    private static void XorBlockSpan(Span<byte> dst, ReadOnlySpan<byte> src)
    {
        for (int i = 0; i < dst.Length; i++) dst[i] ^= src[i];
    }

    private byte[] CcmCtrBlock(ReadOnlySpan<byte> nonce, uint counter)
    {
        byte[] a = new byte[Block];
        a[0] = (byte)(L - 1);
        nonce[..12].CopyTo(a.AsSpan(1));
        WriteBE(a.AsSpan(1 + 12), counter, L);
        return a;
    }

    // ---------------- helpers ----------------

    private static void XorBlock(byte[] dst, byte[] src)
    {
        for (int i = 0; i < Block; i++) dst[i] ^= src[i];
    }

    private static void WriteBE(Span<byte> dst, uint value, int byteCount)
    {
        for (int i = 0; i < byteCount; i++)
            dst[byteCount - 1 - i] = (byte)(value >> (8 * i));
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
