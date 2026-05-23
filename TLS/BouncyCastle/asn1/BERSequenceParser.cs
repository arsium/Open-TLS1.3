#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Check for 'Asn1SequenceParser' instead")]
    public class BerSequenceParser
        : Asn1SequenceParser
    {
        private readonly Asn1StreamParser m_parser;

        internal BerSequenceParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        public Asn1Object ToAsn1Object() => Parse(m_parser);

        internal static BerSequence Parse(Asn1StreamParser sp) => BerSequence.FromVector(sp.ReadVector());
    }
}
