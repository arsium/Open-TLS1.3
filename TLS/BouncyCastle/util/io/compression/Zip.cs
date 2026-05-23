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
    internal static class Zip
    {
        internal static Stream CompressOutput(Stream stream, int zlibCompressionLevel, bool leaveOpen = false)
        {
#if NET6_0_OR_GREATER
            return new DeflateStream(stream, ZLib.GetCompressionLevel(zlibCompressionLevel), leaveOpen);
#else
            return leaveOpen
                ?   new ZOutputStreamLeaveOpen(stream, zlibCompressionLevel, true)
                :   new ZOutputStream(stream, zlibCompressionLevel, true);
#endif
        }

        internal static Stream DecompressInput(Stream stream, bool leaveOpen = false)
        {
#if NET6_0_OR_GREATER
            return new DeflateStream(stream, CompressionMode.Decompress, leaveOpen);
#else
            return leaveOpen
                ?   new ZInputStreamLeaveOpen(stream, true)
                :   new ZInputStream(stream, true);
#endif
        }
    }
}
