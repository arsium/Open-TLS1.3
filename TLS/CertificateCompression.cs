namespace TLS;

using BrotliSharpLib;
using ZstdSharp;

/// <summary>
/// Certificate compression/decompression for RFC 8879.
/// Supports zlib (0x0001) via ZLibDotNet, Brotli (0x0002) via BrotliSharpLib, and
/// Zstandard (0x0003) via ZstdSharp — all pure managed C# ports.
///
/// Every backend is pure-managed: no System.IO.Compression.{ZLib,Brotli}Stream (those
/// P/Invoke native zlib/brotli), no native dependency, no platform-specific code path.
/// This keeps RFC 8879 cert compression working uniformly on every platform .NET runs on.
/// </summary>
public static class CertificateCompression
{
    public const ushort AlgorithmZlib = 0x0001;
    public const ushort AlgorithmBrotli = 0x0002;
    public const ushort AlgorithmZstd = 0x0003;

    // zlib compression level (RFC 1950). 6 = zlib's default speed/ratio balance.
    private const int ZlibLevel = 6;

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
            case AlgorithmZlib:
            {
                // zlib format (RFC 1950) via BouncyCastle's JZlib port. nowrap=false ⇒ zlib wrapper
                // (2-byte header + Adler-32), which is what RFC 8879 algorithm 1 mandates.
                using var outMs = new System.IO.MemoryStream();
                using (var z = new Org.BouncyCastle.Utilities.Zlib.ZOutputStreamLeaveOpen(outMs, ZlibLevel, false))
                    z.Write(data, 0, data.Length); // Dispose flushes (Finish) + ends, leaves outMs open
                return outMs.ToArray();
            }

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
            case AlgorithmZlib:
            {
                // Inflate exactly uncompressedLength bytes (already range-checked above as a
                // decompression-bomb guard), then confirm the stream ends there.
                using var inMs = new System.IO.MemoryStream(compressed);
                using var z = new Org.BouncyCastle.Utilities.Zlib.ZInputStream(inMs, false);
                byte[] result = new byte[uncompressedLength];
                int total = 0;
                while (total < uncompressedLength)
                {
                    int n = z.Read(result, total, uncompressedLength - total);
                    if (n <= 0) break;
                    total += n;
                }
                if (total != uncompressedLength)
                    throw new TlsException(AlertDescription.DecodeError,
                        $"zlib decompression length mismatch: got {total}, expected {uncompressedLength}");
                if (z.Read(new byte[1], 0, 1) > 0)
                    throw new TlsException(AlertDescription.DecodeError,
                        "zlib stream longer than declared uncompressed_length");
                return result;
            }

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
        algorithm == AlgorithmZlib || algorithm == AlgorithmBrotli || algorithm == AlgorithmZstd;
}
