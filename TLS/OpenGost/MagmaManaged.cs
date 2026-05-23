using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Magma (GOST R 34.12-2015) — ECB block cipher facade. Thin wrapper over
/// <see cref="MagmaManagedTransform"/>; no BCL SymmetricAlgorithm inheritance.
/// </summary>
[ComVisible(true)]
public sealed class MagmaManaged : IDisposable
{
    public const int BlockSize = MagmaManagedTransform.BlockSizeBytes;
    public const int KeySize = MagmaManagedTransform.KeySizeBytes;

    private MagmaManagedTransform? _cipher;
    private bool _disposed;

    /// <summary>Create the cipher bound to the given 32-byte key.</summary>
    public MagmaManaged(byte[] key) { _cipher = new MagmaManagedTransform(key); }

    /// <summary>Encrypt one 8-byte block.</summary>
    public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        => _cipher!.EncryptBlock(input, inputOffset, output, outputOffset);

    /// <summary>Decrypt one 8-byte block.</summary>
    public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        => _cipher!.DecryptBlock(input, inputOffset, output, outputOffset);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cipher = null;
    }
}
