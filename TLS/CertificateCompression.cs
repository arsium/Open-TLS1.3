namespace TLS;

using BrotliSharpLib;
using ZstdSharp;

/// <summary>
/// Certificate compression/decompression for RFC 8879.
/// Supports Brotli (0x0002) via BrotliSharpLib (pure managed C# port of google/brotli)
/// and Zstandard (0x0003) via ZstdSharp (pure managed C# port).
///
/// Both backends are pure-managed: no System.IO.Compression.BrotliStream, no native
/// dependency, no platform-specific code path. This keeps RFC 8879 cert compression
/// working uniformly on every platform .NET runs on.
/// </summary>
public static class CertificateCompression
{
    public const ushort AlgorithmBrotli = 0x0002;
    public const ushort AlgorithmZstd = 0x0003;

    // RFC 8879 caps the certificate_list at 2^24-1, but in practice a TLS cert chain
    // is at most a few tens of KB. Reject anything above this to avoid a decompression
    // bomb DoS (uncompressedLength comes straight from the wire).
    public const int MaxUncompressedLength = 256 * 1024;

    // BrotliSharpLib's default quality is 11 (best, slow). Use 4 — a reasonable speed/ratio
    // trade-off for handshake-time certificate compression where the certs are <50 KB and
    // CPU time matters more than the last few percent of compression.
    private const int BrotliQuality = 4;
    private const int BrotliWindow = 22; // default; gives the standard 4 MB ringbuffer

    public static byte[] Compress(byte[] data, ushort algorithm)
    {
        switch (algorithm)
        {
            case AlgorithmBrotli:
                return Brotli.CompressBuffer(data, 0, data.Length, BrotliQuality, BrotliWindow);

            case AlgorithmZstd:
                using (var compressor = new Compressor(3))
                    return compressor.Wrap(data).ToArray();

            default:
                throw new TlsException(AlertDescription.IllegalParameter,
                    $"Unsupported cert compression algorithm: {algorithm}");
        }
    }

    public static byte[] Decompress(byte[] compressed, ushort algorithm, int uncompressedLength)
    {
        if (uncompressedLength <= 0 || uncompressedLength > MaxUncompressedLength)
            throw new TlsException(AlertDescription.BadCertificate,
                $"CompressedCertificate uncompressed_length {uncompressedLength} out of allowed range (0,{MaxUncompressedLength}]");

        switch (algorithm)
        {
            case AlgorithmBrotli:
            {
                byte[] result = Brotli.DecompressBuffer(compressed, 0, compressed.Length);
                if (result.Length != uncompressedLength)
                    throw new TlsException(AlertDescription.DecodeError,
                        $"Brotli decompression length mismatch: got {result.Length}, expected {uncompressedLength}");
                return result;
            }

            case AlgorithmZstd:
                using (var decompressor = new Decompressor())
                {
                    byte[] result = new byte[uncompressedLength];
                    int written = decompressor.Unwrap(compressed, result, 0);
                    if (written != uncompressedLength)
                        throw new TlsException(AlertDescription.DecodeError,
                            "Zstd decompression yielded unexpected byte count");
                    return result;
                }

            default:
                throw new TlsException(AlertDescription.IllegalParameter,
                    $"Unsupported cert compression algorithm: {algorithm}");
        }
    }

    /// <summary>Check if the given algorithm is supported.</summary>
    public static bool IsSupported(ushort algorithm) =>
        algorithm == AlgorithmBrotli || algorithm == AlgorithmZstd;
}
