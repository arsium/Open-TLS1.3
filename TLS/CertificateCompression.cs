namespace TLS;

using System.IO.Compression;
using ZstdSharp;

/// <summary>
/// Certificate compression/decompression for RFC 8879.
/// Supports Brotli (0x0002) via built-in .NET BrotliEncoder
/// and Zstandard (0x0003) via ZstdSharp (pure managed C# port).
/// </summary>
public static class CertificateCompression
{
    public const ushort AlgorithmBrotli = 0x0002;
    public const ushort AlgorithmZstd = 0x0003;

    public static byte[] Compress(byte[] data, ushort algorithm)
    {
        switch (algorithm)
        {
            case AlgorithmBrotli:
                using (var output = new MemoryStream())
                {
                    using (var brotli = new BrotliStream(output, CompressionLevel.Fastest, leaveOpen: true))
                        brotli.Write(data);
                    return output.ToArray();
                }

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
        switch (algorithm)
        {
            case AlgorithmBrotli:
                using (var input = new MemoryStream(compressed))
                using (var brotli = new BrotliStream(input, CompressionMode.Decompress))
                {
                    byte[] result = new byte[uncompressedLength];
                    int offset = 0;
                    while (offset < uncompressedLength)
                    {
                        int read = brotli.Read(result, offset, uncompressedLength - offset);
                        if (read == 0)
                            throw new TlsException(AlertDescription.DecodeError,
                                "Compressed certificate decompression yielded fewer bytes than expected");
                        offset += read;
                    }
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
