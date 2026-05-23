using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Grasshopper / Kuznyechik (GOST R 34.12-2015) — ECB block cipher facade. Thin wrapper
/// over <see cref="GrasshopperManagedTransform"/>; no BCL SymmetricAlgorithm inheritance.
/// </summary>
[ComVisible(true)]
public sealed class GrasshopperManaged : IDisposable
{
    public const int BlockSize = GrasshopperManagedTransform.BlockSizeBytes;
    public const int KeySize = GrasshopperManagedTransform.KeySizeBytes;

    private GrasshopperManagedTransform? _cipher;
    private bool _disposed;

    public GrasshopperManaged(byte[] key) { _cipher = new GrasshopperManagedTransform(key); }

    public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        => _cipher!.EncryptBlock(input, inputOffset, output, outputOffset);

    public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        => _cipher!.DecryptBlock(input, inputOffset, output, outputOffset);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cipher?.Dispose();
        _cipher = null;
    }
}
