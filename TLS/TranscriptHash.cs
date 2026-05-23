namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// Accumulates all handshake messages and computes the transcript hash on demand.
///
/// Two storage modes coexist:
///   * <see cref="_incremental"/> — an <see cref="IncrementalHash"/> for built-in hashes
///     (SHA-256, SHA-384). <see cref="GetHash"/> snapshots it in O(hashLen) per call.
///   * <see cref="_data"/> — a raw byte buffer that always tracks every appended message.
///     Required for: GOST/SM3 custom hashes (no IncrementalHash support), HelloRetryRequest's
///     <see cref="ReplaceWithMessageHash"/> rewrite, <see cref="Clone"/> snapshots, and the
///     mid-handshake <see cref="SetAlgorithm"/> switch which has to replay the prefix.
/// </summary>
public sealed class TranscriptHash
{
    private HashAlgorithmName _algorithm;
    private readonly MemoryStream _data = new();
    private IncrementalSha2? _incremental;

    public int HashLength => Hkdf.HashLen(_algorithm);

    public TranscriptHash(HashAlgorithmName algorithm)
    {
        _algorithm = algorithm;
        _incremental = TryCreateIncremental(algorithm);
    }

    public void SetAlgorithm(HashAlgorithmName algorithm)
    {
        if (_algorithm == algorithm) return;
        _algorithm = algorithm;

        _incremental?.Dispose();
        _incremental = TryCreateIncremental(algorithm);
        if (_incremental != null && _data.Length > 0)
            _incremental.AppendData(GetBufferedSpan());
    }

    /// <summary>Append a complete handshake message (type + length + body).</summary>
    public void Update(byte[] handshakeMessage)
    {
        _data.Write(handshakeMessage);
        _incremental?.AppendData(handshakeMessage);
    }

    /// <summary>
    /// Replace all accumulated data with a synthetic message_hash construct (RFC 8446 §4.4.1).
    /// Used when processing HelloRetryRequest: transcript becomes message_hash(Hash(CH1)).
    /// </summary>
    public void ReplaceWithMessageHash()
    {
        byte[] hash = GetHash();
        _data.SetLength(0);
        _data.WriteByte(254); // HandshakeType.MessageHash
        BinaryHelper.WriteUInt24(_data, (uint)hash.Length);
        _data.Write(hash);

        // Rebuild the incremental view so it stays in sync with _data.
        if (_incremental != null)
        {
            _incremental.Dispose();
            _incremental = TryCreateIncremental(_algorithm);
            _incremental?.AppendData(GetBufferedSpan());
        }
    }

    /// <summary>Create a snapshot copy of this transcript (for PSK binder computation after HRR).</summary>
    public TranscriptHash Clone()
    {
        var clone = new TranscriptHash(_algorithm);
        var span = GetBufferedSpan();
        if (span.Length > 0)
        {
            clone._data.Write(span);
            clone._incremental?.AppendData(span);
        }
        return clone;
    }

    /// <summary>Compute the current transcript hash without consuming the data.</summary>
    public byte[] GetHash()
    {
        if (_incremental != null)
            return _incremental.GetCurrentHash();

        // Fallback for Streebog / SM3, which aren't .NET-managed hashes.
        var span = GetBufferedSpan();
        if (GostKdf.IsStreebog(_algorithm)) return GostKdf.Hash(span.ToArray());
        if (Sm3Kdf.IsSm3(_algorithm)) return Sm3Kdf.Hash(span.ToArray());
        throw new ArgumentException($"Unsupported hash: {_algorithm}");
    }

    // MemoryStream.GetBuffer() avoids the allocation that ToArray() would do.
    private ReadOnlySpan<byte> GetBufferedSpan() =>
        _data.GetBuffer().AsSpan(0, (int)_data.Length);

    private static IncrementalSha2? TryCreateIncremental(HashAlgorithmName alg)
    {
        if (alg == HashAlgorithmName.SHA256) return IncrementalSha2.CreateSha256();
        if (alg == HashAlgorithmName.SHA384) return IncrementalSha2.CreateSha384();
        if (alg == HashAlgorithmName.SHA512) return IncrementalSha2.CreateSha512();
        return null;
    }
}
