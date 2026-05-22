namespace TLS;

using System.Buffers.Binary;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography;

/// <summary>
/// Multilinear Galois Mode (MGM) AEAD over a GOST block cipher, per RFC 9058.
/// Used by the RFC 9367 TLS 1.3 GOST cipher suites (Kuznyechik n=16, Magma n=8).
/// The field GF(2^8n) is non-reflected (MSB-first); reduction polynomial low byte
/// is 0x87 for n=16 and 0x1B for n=8.
/// </summary>
public sealed class Mgm : IDisposable
{
    private readonly SymmetricAlgorithm _alg;
    private readonly ICryptoTransform _enc;
    private readonly int _n;        // block size in bytes (16 or 8)
    private readonly int _tagLen;   // tag length in bytes
    private readonly byte _reduce;  // GF reduction low byte

    public Mgm(byte[] key, bool kuznyechik, int tagLen)
    {
        _alg = kuznyechik ? new GrasshopperManaged() : new MagmaManaged();
        _alg.Mode = CipherMode.ECB;
        _alg.Padding = PaddingMode.None;
        _alg.Key = key;
        _enc = _alg.CreateEncryptor();
        _n = kuznyechik ? 16 : 8;
        _reduce = (byte)(kuznyechik ? 0x87 : 0x1B);
        _tagLen = tagLen;
    }

    public int TagLength => _tagLen;
    public int NonceLength => _n;

    /// <summary>Encrypt; returns ciphertext ‖ tag.</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        byte[] ct = new byte[plaintext.Length];
        Ctr(nonce, plaintext, ct);
        byte[] tag = ComputeTag(nonce, aad, ct);
        byte[] result = new byte[ct.Length + _tagLen];
        Buffer.BlockCopy(ct, 0, result, 0, ct.Length);
        Buffer.BlockCopy(tag, 0, result, ct.Length, _tagLen);
        return result;
    }

    /// <summary>Decrypt ciphertext ‖ tag; verifies the tag.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad)
    {
        if (!TryDecrypt(nonce, encrypted, aad, out var pt))
            throw new CryptographicException("MGM authentication tag mismatch");
        return pt!;
    }

    public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> aad, out byte[]? plaintext)
    {
        plaintext = null;
        int ctLen = encrypted.Length - _tagLen;
        if (ctLen < 0) return false;

        var ct = encrypted[..ctLen];
        var tag = encrypted[ctLen..];
        byte[] expected = ComputeTag(nonce, aad, ct);
        if (!CryptographicOperations.FixedTimeEquals(tag, expected)) return false;

        byte[] pt = new byte[ctLen];
        Ctr(nonce, ct, pt);
        plaintext = pt;
        return true;
    }

    // CTR encryption layer: Y_1 = E(0 || ICN), Y_i = incr_r(Y_{i-1}); out = in XOR E(Y_i).
    private void Ctr(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length == 0) return;
        byte[] seed = new byte[_n];
        nonce.Slice(0, _n).CopyTo(seed);
        seed[0] &= 0x7f; // 0^1 || ICN
        byte[] y = new byte[_n];
        E(seed, y); // Y_1 = E(0^1 || ICN)
        byte[] gamma = new byte[_n];
        for (int off = 0; off < input.Length; off += _n)
        {
            E(y, gamma);
            int blk = Math.Min(_n, input.Length - off);
            for (int i = 0; i < blk; i++)
                output[off + i] = (byte)(input[off + i] ^ gamma[i]);
            IncrR(y);
        }
    }

    // Tag: Z_1 = E(1 || ICN); sum ^= H_i (x) block; T = MSB_S(E(sum ^ H_last (x) (len(A)||len(C)))).
    private byte[] ComputeTag(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ct)
    {
        byte[] seed = new byte[_n];
        nonce.Slice(0, _n).CopyTo(seed);
        seed[0] |= 0x80; // 1^1 || ICN
        byte[] z = new byte[_n];
        E(seed, z); // Z_1 = E(1^1 || ICN)

        byte[] sum = new byte[_n];
        byte[] h = new byte[_n];
        byte[] block = new byte[_n];

        // Associated data blocks (zero-padded).
        for (int off = 0; off < aad.Length; off += _n)
        {
            E(z, h);
            int blk = Math.Min(_n, aad.Length - off);
            Array.Clear(block, 0, _n);
            aad.Slice(off, blk).CopyTo(block);
            XorInto(sum, GfMul(h, block));
            IncrL(z);
        }

        // Ciphertext blocks (zero-padded).
        for (int off = 0; off < ct.Length; off += _n)
        {
            E(z, h);
            int blk = Math.Min(_n, ct.Length - off);
            Array.Clear(block, 0, _n);
            ct.Slice(off, blk).CopyTo(block);
            XorInto(sum, GfMul(h, block));
            IncrL(z);
        }

        // Length block: len(A) || len(C), each n/2 bytes, big-endian bit lengths.
        E(z, h);
        byte[] lenBlock = new byte[_n];
        WriteBitLen(lenBlock, 0, (ulong)aad.Length * 8, _n / 2);
        WriteBitLen(lenBlock, _n / 2, (ulong)ct.Length * 8, _n / 2);
        XorInto(sum, GfMul(h, lenBlock));

        byte[] full = new byte[_n];
        E(sum, full);
        byte[] tag = new byte[_tagLen];
        Array.Copy(full, 0, tag, 0, _tagLen); // MSB_S
        return tag;
    }

    private void E(byte[] inBlock, byte[] outBlock) => _enc.TransformBlock(inBlock, 0, _n, outBlock, 0);

    // incr_r: increment the right (lower) n/2 bytes as a big-endian integer.
    private void IncrR(byte[] a)
    {
        for (int i = _n - 1; i >= _n / 2; i--)
            if (++a[i] != 0) break;
    }

    // incr_l: increment the left (upper) n/2 bytes as a big-endian integer.
    private void IncrL(byte[] a)
    {
        for (int i = _n / 2 - 1; i >= 0; i--)
            if (++a[i] != 0) break;
    }

    private static void XorInto(byte[] dst, byte[] src)
    {
        for (int i = 0; i < dst.Length; i++) dst[i] ^= src[i];
    }

    private static void WriteBitLen(byte[] buf, int offset, ulong bitLen, int byteCount)
    {
        for (int i = 0; i < byteCount; i++)
            buf[offset + byteCount - 1 - i] = (byte)(bitLen >> (8 * i));
    }

    // GF(2^8n) multiply, MSB-first basis (Horner over b from high to low degree).
    // Packed into big-endian ulongs: n=16 → (hi,lo); n=8 → lo only.
    private byte[] GfMul(byte[] a, byte[] b)
    {
        byte[] z = new byte[_n];
        if (_n == 16)
        {
            ulong aHi = BinaryPrimitives.ReadUInt64BigEndian(a);
            ulong aLo = BinaryPrimitives.ReadUInt64BigEndian(a.AsSpan(8));
            ulong bHi = BinaryPrimitives.ReadUInt64BigEndian(b);
            ulong bLo = BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(8));
            ulong zHi = 0, zLo = 0;
            for (int i = 0; i < 64; i++)
            {
                ulong carry = zHi >> 63;
                zHi = (zHi << 1) | (zLo >> 63); zLo <<= 1;
                if (carry != 0) zLo ^= 0x87;
                if (((bHi >> (63 - i)) & 1) != 0) { zHi ^= aHi; zLo ^= aLo; }
            }
            for (int i = 0; i < 64; i++)
            {
                ulong carry = zHi >> 63;
                zHi = (zHi << 1) | (zLo >> 63); zLo <<= 1;
                if (carry != 0) zLo ^= 0x87;
                if (((bLo >> (63 - i)) & 1) != 0) { zHi ^= aHi; zLo ^= aLo; }
            }
            BinaryPrimitives.WriteUInt64BigEndian(z, zHi);
            BinaryPrimitives.WriteUInt64BigEndian(z.AsSpan(8), zLo);
        }
        else // n == 8 (Magma)
        {
            ulong av = BinaryPrimitives.ReadUInt64BigEndian(a);
            ulong bv = BinaryPrimitives.ReadUInt64BigEndian(b);
            ulong zv = 0;
            for (int i = 0; i < 64; i++)
            {
                ulong carry = zv >> 63;
                zv <<= 1;
                if (carry != 0) zv ^= 0x1B;
                if (((bv >> (63 - i)) & 1) != 0) zv ^= av;
            }
            BinaryPrimitives.WriteUInt64BigEndian(z, zv);
        }
        return z;
    }

    public void Dispose()
    {
        _enc.Dispose();
        _alg.Dispose();
    }
}
