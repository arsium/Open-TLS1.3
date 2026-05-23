namespace TLS;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// SHA-256, SHA-384, SHA-512 + HMAC-SHA wrappers backed by BouncyCastle digests.
/// HMAC-SHA1 is here only for legacy PKCS#12 MAC compatibility (not a TLS primitive).
/// One-shot APIs (HashData, ComputeHash) mirror System.Security.Cryptography; BC digests
/// expose <c>BlockUpdate(ReadOnlySpan&lt;byte&gt;)</c> so we never copy the input to a heap
/// array — important for HKDF and per-record HMAC paths.
/// </summary>
internal static class Sha2Managed
{
    public static byte[] HmacSha1(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        => ComputeHmac(new Sha1Digest(), key, data);

    public static byte[] Sha256(ReadOnlySpan<byte> data)
    {
        var d = new Sha256Digest();
        if (!data.IsEmpty) d.BlockUpdate(data);
        byte[] result = new byte[d.GetDigestSize()];
        d.DoFinal(result, 0);
        return result;
    }

    public static byte[] Sha384(ReadOnlySpan<byte> data)
    {
        var d = new Sha384Digest();
        if (!data.IsEmpty) d.BlockUpdate(data);
        byte[] result = new byte[d.GetDigestSize()];
        d.DoFinal(result, 0);
        return result;
    }

    public static byte[] Sha512(ReadOnlySpan<byte> data)
    {
        var d = new Sha512Digest();
        if (!data.IsEmpty) d.BlockUpdate(data);
        byte[] result = new byte[d.GetDigestSize()];
        d.DoFinal(result, 0);
        return result;
    }

    public static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        => ComputeHmac(new Sha256Digest(), key, data);

    public static byte[] HmacSha384(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        => ComputeHmac(new Sha384Digest(), key, data);

    public static byte[] HmacSha512(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        => ComputeHmac(new Sha512Digest(), key, data);

    private static byte[] ComputeHmac(IDigest inner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        // BC's KeyParameter constructor takes byte[]; one allocation is unavoidable for the key.
        // Past that, BlockUpdate(ReadOnlySpan) on data avoids a second copy.
        var h = new HMac(inner);
        h.Init(new KeyParameter(key.ToArray()));
        if (!data.IsEmpty) h.BlockUpdate(data);
        byte[] result = new byte[h.GetMacSize()];
        h.DoFinal(result, 0);
        return result;
    }
}

/// <summary>
/// Digest-only incremental SHA-2 wrapper that mirrors System.Security.Cryptography.IncrementalHash
/// for the subset TranscriptHash needs: AppendData + GetCurrentHash (true snapshot via digest clone).
/// HMAC mode was removed — no caller used it, and BC's HMac has no clean snapshot primitive.
/// For one-shot HMAC use <see cref="Sha2Managed.HmacSha256"/> / 384 / 512.
/// </summary>
internal sealed class IncrementalSha2 : IDisposable
{
    private readonly IDigest _digest;
    private bool _disposed;

    private IncrementalSha2(IDigest digest) { _digest = digest; }

    public static IncrementalSha2 CreateSha256() => new IncrementalSha2(new Sha256Digest());
    public static IncrementalSha2 CreateSha384() => new IncrementalSha2(new Sha384Digest());
    public static IncrementalSha2 CreateSha512() => new IncrementalSha2(new Sha512Digest());

    public int HashSize => _digest.GetDigestSize();

    public void AppendData(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        _digest.BlockUpdate(data);
    }

    public void AppendData(byte[] data, int offset, int count)
    {
        if (count <= 0) return;
        _digest.BlockUpdate(data, offset, count);
    }

    /// <summary>Snapshot the current hash without consuming the accumulator.</summary>
    public byte[] GetCurrentHash()
    {
        byte[] result = new byte[_digest.GetDigestSize()];
        var snap = CloneDigest(_digest);
        snap.DoFinal(result, 0);
        return result;
    }

    private static IDigest CloneDigest(IDigest d) => d switch
    {
        Sha256Digest s256 => new Sha256Digest(s256),
        Sha384Digest s384 => new Sha384Digest(s384),
        Sha512Digest s512 => new Sha512Digest(s512),
        _ => throw new NotSupportedException($"Cannot clone digest: {d.GetType()}")
    };

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // BC digests don't expose state; GC reclaims.
    }
}
