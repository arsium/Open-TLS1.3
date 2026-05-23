#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.IO;

namespace Org.BouncyCastle.Utilities.IO.Compression
{
    using Impl = Utilities.Bzip2;

    internal static class Bzip2
    {
        internal static Stream CompressOutput(Stream stream, bool leaveOpen = false)
        {
            return leaveOpen
                ?   new Impl.CBZip2OutputStreamLeaveOpen(stream)
                :   new Impl.CBZip2OutputStream(stream);
        }

        internal static Stream DecompressInput(Stream stream, bool leaveOpen = false)
        {
            return leaveOpen
                ?   new Impl.CBZip2InputStreamLeaveOpen(stream)
                :   new Impl.CBZip2InputStream(stream);
        }
    }
}
