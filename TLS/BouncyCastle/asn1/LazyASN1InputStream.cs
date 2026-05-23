#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <remarks>No longer provides any laziness.</remarks>
    [Obsolete("Will be removed")]
    public class LazyAsn1InputStream
        : Asn1InputStream
    {
        public LazyAsn1InputStream(byte[] input)
            : base(input)
        {
        }

        public LazyAsn1InputStream(Stream inputStream)
            : base(inputStream)
        {
        }

        public LazyAsn1InputStream(Stream input, int limit)
            : base(input, limit)
        {
        }

        public LazyAsn1InputStream(Stream input, int limit, bool leaveOpen)
            : base(input, limit, leaveOpen)
        {
        }
    }
}
