using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Streebog-256 (GOST R 34.11-2012, half-length variant). Standalone class — no longer
/// inherits from System.Security.Cryptography.HashAlgorithm so the BCL hash registry
/// (and its BCrypt imports) doesn't get linked. Internally wraps a Streebog512Managed
/// seeded with the 256-bit IV; the 32-byte output is the upper half of the 64-byte digest.
/// </summary>
[ComVisible(true)]
public sealed class Streebog256Managed : IDisposable
{
    public const int HashSize = 32;
    public byte[]? HashValue { get; private set; }

    private static readonly byte[] _defaultIV =
    [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    ];

    private readonly Streebog512Managed _innerAlgorithm = new(_defaultIV);
    private bool _disposed;

    public static byte[] Hash(byte[] data)
    {
        var h = new Streebog256Managed();
        h.BlockUpdate(data, 0, data.Length);
        var result = new byte[HashSize];
        h.DoFinal(result, 0);
        return result;
    }

    public void Initialize() => _innerAlgorithm.Initialize();

    public void BlockUpdate(byte[] data, int offset, int count)
        => _innerAlgorithm.TransformBlock(data, offset, count, null, 0);

    public int DoFinal(byte[] output, int offset)
    {
        _ = _innerAlgorithm.TransformFinalBlock([], 0, 0);
        // Streebog-256 takes the upper half (bytes 32..64) of the Streebog-512 state.
        Buffer.BlockCopy(_innerAlgorithm.HashValue!, 32, output, offset, HashSize);
        var hash = new byte[HashSize];
        Buffer.BlockCopy(_innerAlgorithm.HashValue!, 32, hash, 0, HashSize);
        HashValue = hash;
        return HashSize;
    }

    // Compat shims for the few callers that used the old HashAlgorithm-style names.
    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        if (inputCount > 0) BlockUpdate(inputBuffer, inputOffset, inputCount);
        var hash = new byte[HashSize];
        DoFinal(hash, 0);
        var copy = new byte[inputCount];
        if (inputCount > 0) Buffer.BlockCopy(inputBuffer, inputOffset, copy, 0, inputCount);
        return copy;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (HashValue != null) Array.Clear(HashValue, 0, HashValue.Length);
        _innerAlgorithm.Dispose();
    }
}
