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
    private readonly GrasshopperManaged? _kuz;
    private readonly MagmaManaged? _mag;
    private readonly int _n;        // block size in bytes (16 or 8)
    private readonly int _tagLen;   // tag length in bytes
    private readonly byte _reduce;  // GF reduction low byte

    public Mgm(byte[] key, bool kuznyechik, int tagLen)
    {
        if (kuznyechik) _kuz = new GrasshopperManaged(key);
        else            _mag = new MagmaManaged(key);
        _n = kuznyechik ? 16 : 8;
        _reduce = (byte)(kuznyechik ? 0x87 : 0x1B);
        _tagLen = tagLen;
    }

    public int TagLength => _tagLen;
    public int NonceLength => _n;

    /// <summary>Encrypt; returns ciphertext ‖ tag. Allocates the result; for the hot
    /// per-record path prefer <see cref="EncryptInto"/> which writes into a caller-owned
    /// span (saves one full plaintext-sized allocation per call).</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        byte[] result = new byte[plaintext.Length + _tagLen];
        EncryptInto(nonce, plaintext, result, aad);
        return result;
    }

    /// <summary>
    /// Encrypt directly into <paramref name="output"/> = ciphertext||tag. <c>output.Length</c>
    /// MUST equal <c>plaintext.Length + TagLength</c>. Matches the layout of AesGcmManaged /
    /// ChaCha20Poly1305Managed for uniform dispatch from <see cref="AeadCipher"/>.
    /// </summary>
    public void EncryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        Span<byte> output, ReadOnlySpan<byte> aad)
    {
        if (output.Length != plaintext.Length + _tagLen)
            throw new ArgumentException($"output must be plaintext.Length + {_tagLen} bytes");
        var ctSpan = output.Slice(0, plaintext.Length);
        var tagSpan = output.Slice(plaintext.Length, _tagLen);
        Ctr(nonce, plaintext, ctSpan);
        ComputeTagInto(nonce, aad, ctSpan, tagSpan);
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

        byte[] pt = new byte[ctLen];
        if (!TryDecryptInto(nonce, encrypted, pt, aad))
            return false;
        plaintext = pt;
        return true;
    }

    /// <summary>
    /// Verify and decrypt <paramref name="ctAndTag"/> straight into <paramref name="plaintext"/>.
    /// Returns false on tag mismatch (caller is then responsible for not using <paramref name="plaintext"/>).
    /// </summary>
    public bool TryDecryptInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ctAndTag,
        Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        int ctLen = ctAndTag.Length - _tagLen;
        if (ctLen < 0 || plaintext.Length != ctLen) return false;

        var ct = ctAndTag.Slice(0, ctLen);
        var tag = ctAndTag.Slice(ctLen);
        Span<byte> expected = stackalloc byte[_tagLen];
        ComputeTagInto(nonce, aad, ct, expected);
        if (!CryptographicOperations.FixedTimeEquals(tag, expected)) return false;

        Ctr(nonce, ct, plaintext);
        return true;
    }

    // CTR encryption layer: Y_1 = E(0 || ICN), Y_i = incr_r(Y_{i-1}); out = in XOR E(Y_i).
    private void Ctr(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length == 0) return;
        // Working buffers allocated once per call. The block cipher's EncryptBlock takes
        // byte[] (defined by GrasshopperManaged/MagmaManaged), so we keep these as byte[]
        // — but reused across every loop iteration instead of per-iteration freshness.
        byte[] seed = new byte[_n];
        byte[] y = new byte[_n];
        byte[] gamma = new byte[_n];

        nonce.Slice(0, _n).CopyTo(seed);
        seed[0] &= 0x7f; // 0^1 || ICN
        E(seed, y); // Y_1 = E(0^1 || ICN)
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
    // Output writes the first _tagLen bytes of MSB_S into `tag`.
    private void ComputeTagInto(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ct, Span<byte> tag)
    {
        // All working buffers allocated ONCE per Encrypt call and reused across both AAD
        // and ciphertext loops. Previously each iteration's GfMul allocated a new byte[_n]
        // (1024+ allocations for a 16 KB ciphertext under Kuznyechik) — that single change
        // was ~41 KB/op of the measured 74 KB/op overhead.
        byte[] seed = new byte[_n];
        byte[] z = new byte[_n];
        byte[] sum = new byte[_n];
        byte[] h = new byte[_n];
        byte[] block = new byte[_n];
        byte[] gfTmp = new byte[_n];
        byte[] full = new byte[_n];

        nonce.Slice(0, _n).CopyTo(seed);
        seed[0] |= 0x80; // 1^1 || ICN
        E(seed, z); // Z_1 = E(1^1 || ICN)

        // Associated data blocks (zero-padded).
        for (int off = 0; off < aad.Length; off += _n)
        {
            E(z, h);
            int blk = Math.Min(_n, aad.Length - off);
            Array.Clear(block, 0, _n);
            aad.Slice(off, blk).CopyTo(block);
            GfMulInto(h, block, gfTmp);
            XorInto(sum, gfTmp);
            IncrL(z);
        }

        // Ciphertext blocks (zero-padded).
        for (int off = 0; off < ct.Length; off += _n)
        {
            E(z, h);
            int blk = Math.Min(_n, ct.Length - off);
            Array.Clear(block, 0, _n);
            ct.Slice(off, blk).CopyTo(block);
            GfMulInto(h, block, gfTmp);
            XorInto(sum, gfTmp);
            IncrL(z);
        }

        // Length block: len(A) || len(C), each n/2 bytes, big-endian bit lengths.
        E(z, h);
        // Reuse `block` as the length block buffer; we no longer need it for ct/aad data.
        Array.Clear(block, 0, _n);
        WriteBitLen(block, 0, (ulong)aad.Length * 8, _n / 2);
        WriteBitLen(block, _n / 2, (ulong)ct.Length * 8, _n / 2);
        GfMulInto(h, block, gfTmp);
        XorInto(sum, gfTmp);

        E(sum, full);
        full.AsSpan(0, _tagLen).CopyTo(tag); // MSB_S
    }

    private void E(byte[] inBlock, byte[] outBlock)
    {
        if (_kuz != null) _kuz.EncryptBlock(inBlock, 0, outBlock, 0);
        else              _mag!.EncryptBlock(inBlock, 0, outBlock, 0);
    }

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
    // Writes into `z` instead of returning a fresh byte[] — this is the hot inner loop
    // of the AEAD tag (one call per ciphertext block), and per-block allocation was the
    // single biggest contributor to MGM's allocation rate.
    private void GfMulInto(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> z)
    {
        if (_n == 16)
        {
            ulong aHi = BinaryPrimitives.ReadUInt64BigEndian(a);
            ulong aLo = BinaryPrimitives.ReadUInt64BigEndian(a.Slice(8));
            ulong bHi = BinaryPrimitives.ReadUInt64BigEndian(b);
            ulong bLo = BinaryPrimitives.ReadUInt64BigEndian(b.Slice(8));
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
            BinaryPrimitives.WriteUInt64BigEndian(z.Slice(8), zLo);
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
    }

    public void Dispose()
    {
        _kuz?.Dispose();
        _mag?.Dispose();
    }
}
