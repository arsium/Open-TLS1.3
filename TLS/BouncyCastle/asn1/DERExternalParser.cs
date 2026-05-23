#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1
{
    // TODO[asn1] Replace with BerExternalParser, DLExternalParser (currently functions as DLExternalParser already)
    public class DerExternalParser
        : Asn1Encodable
    {
        private readonly Asn1StreamParser m_parser;

        internal DerExternalParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        public override Asn1Object ToAsn1Object() => Parse(m_parser);

        internal static DLExternal Parse(Asn1StreamParser sp)
        {
            var seq = new DLSequence(sp.ReadVector());

            try
            {
                return DLExternal.FromSequence(seq);
            }
            catch (ArgumentException e)
            {
                throw new Asn1Exception("corrupted stream detected", e);
            }
        }
    }
}
