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
        => _ccm ? CcmEncrypt(nonce, plaintext, aad) : GcmEncrypt(nonce, plaintext, aad);

    public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, out byte[]? plaintext)
        => _ccm ? CcmTryDecrypt(nonce, encrypted, aad, out plaintext)
                : GcmTryDecrypt(nonce, encrypted, aad, out plaintext);

    public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad)
    {
        if (!TryDecrypt(nonce, encrypted, aad, out var pt))
            throw new CryptographicException("SM4 AEAD authentication tag mismatch");
        return pt!;
    }

    private void E(ReadOnlySpan<byte> input, Span<byte> output) => ChineseCrypto.SM4.EncryptBlock(_rk, input, output);

    // ---------------- GCM ----------------

    private byte[] GcmEncrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pt, ReadOnlySpan<byte> aad)
    {
        byte[] j0 = GcmJ0(nonce);
        byte[] ct = new byte[pt.Length];
        Gctr(j0, increment: true, pt, ct);

        byte[] s = GHash(aad, ct);
        byte[] ej0 = new byte[Block];
        E(j0, ej0);
        byte[] tag = new byte[_tagLen];
        for (int i = 0; i < _tagLen; i++) tag[i] = (byte)(s[i] ^ ej0[i]);

        return Concat(ct, tag);
    }

    private bool GcmTryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> enc, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        plaintext = null;
        int ctLen = enc.Length - _tagLen;
        if (ctLen < 0) return false;
        var ct = enc[..ctLen];
        var tag = enc[ctLen..];

        byte[] j0 = GcmJ0(nonce);
        byte[] s = GHash(aad, ct);
        byte[] ej0 = new byte[Block];
        E(j0, ej0);
        byte[] expected = new byte[_tagLen];
        for (int i = 0; i < _tagLen; i++) expected[i] = (byte)(s[i] ^ ej0[i]);
        if (!CryptographicOperations.FixedTimeEquals(tag, expected)) return false;

        byte[] pt = new byte[ctLen];
        Gctr(j0, increment: true, ct, pt);
        plaintext = pt;
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

    private byte[] GHash(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ct)
    {
        ulong yHi = 0, yLo = 0;
        GHashBlocks(ref yHi, ref yLo, aad);
        GHashBlocks(ref yHi, ref yLo, ct);
        // length block: len(A) || len(C) in bits, big-endian
        yHi ^= (ulong)aad.Length * 8;
        yLo ^= (ulong)ct.Length * 8;
        GfMul(ref yHi, ref yLo);
        byte[] y = new byte[Block];
        BinaryPrimitives.WriteUInt64BigEndian(y, yHi);
        BinaryPrimitives.WriteUInt64BigEndian(y.AsSpan(8), yLo);
        return y;
    }

    private void GHashBlocks(ref ulong yHi, ref ulong yLo, ReadOnlySpan<byte> data)
    {
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
                Span<byte> tmp = stackalloc byte[Block];
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

    private byte[] CcmEncrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pt, ReadOnlySpan<byte> aad)
    {
        byte[] tag = CcmMac(nonce, pt, aad);          // T (16) before S0 XOR
        byte[] s0 = CcmKeystream0(nonce);
        byte[] u = new byte[_tagLen];
        for (int i = 0; i < _tagLen; i++) u[i] = (byte)(tag[i] ^ s0[i]);

        byte[] ct = new byte[pt.Length];
        CcmCtr(nonce, pt, ct);
        return Concat(ct, u);
    }

    private bool CcmTryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> enc, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        plaintext = null;
        int ctLen = enc.Length - _tagLen;
        if (ctLen < 0) return false;
        var ct = enc[..ctLen];
        var tag = enc[ctLen..];

        byte[] pt = new byte[ctLen];
        CcmCtr(nonce, ct, pt);

        byte[] t = CcmMac(nonce, pt, aad);
        byte[] s0 = CcmKeystream0(nonce);
        byte[] expected = new byte[_tagLen];
        for (int i = 0; i < _tagLen; i++) expected[i] = (byte)(t[i] ^ s0[i]);
        if (!CryptographicOperations.FixedTimeEquals(tag, expected)) return false;

        plaintext = pt;
        return true;
    }

    private int L => 15 - 12; // nonce is 12 bytes ⇒ L = 3

    private byte[] CcmMac(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pt, ReadOnlySpan<byte> aad)
    {
        // B0 = flags || nonce || Q
        byte[] b0 = new byte[Block];
        int mPrime = (_tagLen - 2) / 2;
        b0[0] = (byte)((aad.Length > 0 ? 0x40 : 0) | (mPrime << 3) | (L - 1));
        nonce[..12].CopyTo(b0.AsSpan(1));
        WriteBE(b0.AsSpan(1 + 12), (uint)pt.Length, L);

        byte[] t = new byte[Block];
        E(b0, t); // T = E(B0)

        if (aad.Length > 0)
        {
            // associated data: 2-byte BE length prefix (for len < 2^16-2^8), then aad, zero-padded
            byte[] enc = new byte[2 + aad.Length];
            BinaryPrimitives.WriteUInt16BigEndian(enc, (ushort)aad.Length);
            aad.CopyTo(enc.AsSpan(2));
            CbcMacBlocks(t, enc);
        }
        CbcMacBlocks(t, pt);
        return t;
    }

    private void CbcMacBlocks(byte[] t, ReadOnlySpan<byte> data)
    {
        byte[] block = new byte[Block];
        for (int off = 0; off < data.Length; off += Block)
        {
            int blk = Math.Min(Block, data.Length - off);
            block.AsSpan().Clear();
            data.Slice(off, blk).CopyTo(block);
            XorBlock(t, block);
            byte[] o = new byte[Block];
            E(t, o);
            Buffer.BlockCopy(o, 0, t, 0, Block);
        }
    }

    private byte[] CcmKeystream0(ReadOnlySpan<byte> nonce)
    {
        byte[] a0 = CcmCtrBlock(nonce, 0);
        byte[] s0 = new byte[Block];
        E(a0, s0);
        return s0;
    }

    private void CcmCtr(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
    {
        byte[] ks = new byte[Block];
        int counter = 1;
        for (int off = 0; off < input.Length; off += Block, counter++)
        {
            byte[] a = CcmCtrBlock(nonce, (uint)counter);
            E(a, ks);
            int blk = Math.Min(Block, input.Length - off);
            for (int i = 0; i < blk; i++) output[off + i] = (byte)(input[off + i] ^ ks[i]);
        }
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
