#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public class DerOctetStringParser
        : Asn1OctetStringParser
    {
        private readonly DefiniteLengthInputStream m_stream;

        internal DerOctetStringParser(DefiniteLengthInputStream stream)
        {
            m_stream = stream;
        }

        public Stream GetOctetStream() => m_stream;

        public Asn1Object ToAsn1Object()
        {
            try
            {
                return DerOctetString.WithContents(m_stream.ToArray());
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("IOException converting stream to byte array: " + e.Message, e);
            }
        }
    }
}
