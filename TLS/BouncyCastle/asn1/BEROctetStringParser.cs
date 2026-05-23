#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Check for 'Asn1OctetStringParser' instead")]
    public class BerOctetStringParser
        : Asn1OctetStringParser
    {
        private readonly Asn1StreamParser m_parser;

        internal BerOctetStringParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        public Stream GetOctetStream() => new ConstructedOctetStream(m_parser);

        public Asn1Object ToAsn1Object()
        {
            try
            {
                return Parse(m_parser);
            }
            catch (IOException e)
            {
                throw new Asn1ParsingException("IOException converting stream to byte array", e);
            }
        }

        internal static BerOctetString Parse(Asn1StreamParser sp) =>
            new BerOctetString(Streams.ReadAll(new ConstructedOctetStream(sp)));
    }
}
