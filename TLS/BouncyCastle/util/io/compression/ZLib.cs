#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.IO;

#if NET6_0_OR_GREATER
using System.IO.Compression;
#else
using Org.BouncyCastle.Utilities.Zlib;
#endif

namespace Org.BouncyCastle.Utilities.IO.Compression
{
    internal static class ZLib
    {
        internal static Stream CompressOutput(Stream stream, int zlibCompressionLevel, bool leaveOpen = false)
        {
#if NET6_0_OR_GREATER
            return new ZLibStream(stream, GetCompressionLevel(zlibCompressionLevel), leaveOpen);
#else
            return leaveOpen
                ?   new ZOutputStreamLeaveOpen(stream, zlibCompressionLevel, false)
                :   new ZOutputStream(stream, zlibCompressionLevel, false);
#endif
        }

        internal static Stream DecompressInput(Stream stream, bool leaveOpen = false)
        {
#if NET6_0_OR_GREATER
            return new ZLibStream(stream, CompressionMode.Decompress, leaveOpen);
#else
            return leaveOpen
                ?   new ZInputStreamLeaveOpen(stream)
                :   new ZInputStream(stream);
#endif
        }

#if NET6_0_OR_GREATER
        internal static CompressionLevel GetCompressionLevel(int zlibCompressionLevel)
        {
            return zlibCompressionLevel switch
            {
                0           => CompressionLevel.NoCompression,
                1 or 2 or 3 => CompressionLevel.Fastest,
                7 or 8 or 9 => CompressionLevel.SmallestSize,
                _           => CompressionLevel.Optimal,
            };
        }
#endif
    }
}
