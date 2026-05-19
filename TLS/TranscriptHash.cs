namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// Accumulates all handshake messages and computes the transcript hash on demand.
/// The hash algorithm can be changed after construction (needed because the cipher
/// suite — and therefore the hash — is not known until ServerHello is parsed).
/// </summary>
public sealed class TranscriptHash
{
    private HashAlgorithmName _algorithm;
    private readonly MemoryStream _data = new();

    public int HashLength => Hkdf.HashLen(_algorithm);

    public TranscriptHash(HashAlgorithmName algorithm)
    {
        _algorithm = algorithm;
    }

    public void SetAlgorithm(HashAlgorithmName algorithm)
    {
        _algorithm = algorithm;
    }

    /// <summary>Append a complete handshake message (type + length + body).</summary>
    public void Update(byte[] handshakeMessage)
    {
        _data.Write(handshakeMessage);
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
    }

    /// <summary>Create a snapshot copy of this transcript (for PSK binder computation after HRR).</summary>
    public TranscriptHash Clone()
    {
        var clone = new TranscriptHash(_algorithm);
        clone._data.Write(_data.ToArray());
        return clone;
    }

    /// <summary>Compute the current transcript hash without consuming the data.</summary>
    public byte[] GetHash()
    {
        byte[] all = _data.ToArray();
        if (_algorithm == HashAlgorithmName.SHA256) return SHA256.HashData(all);
        if (_algorithm == HashAlgorithmName.SHA384) return SHA384.HashData(all);
        throw new ArgumentException($"Unsupported hash: {_algorithm}");
    }
}
