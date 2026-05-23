#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for definite-length tagged objects.</summary>
    internal class DLTaggedObjectParser
        : BerTaggedObjectParser
    {
        private readonly bool m_constructed;

        internal DLTaggedObjectParser(int tagClass, int tagNo, bool constructed, Asn1StreamParser parser)
            : base(tagClass, tagNo, parser)
        {
            m_constructed = constructed;
        }

        public override bool IsConstructed => m_constructed;

        public override IAsn1Convertible ParseBaseUniversal(bool declaredExplicit, int baseTagNo)
        {
            if (declaredExplicit)
                return CheckConstructed().ParseObject(baseTagNo);

            return m_constructed
                ?  m_parser.ParseImplicitConstructedDL(baseTagNo)
                :  m_parser.ParseImplicitPrimitive(baseTagNo);
        }

        public override IAsn1Convertible ParseExplicitBaseObject() => CheckConstructed().ReadObject();

        public override Asn1TaggedObjectParser ParseExplicitBaseTagged() => CheckConstructed().ParseTaggedObject();

        public override Asn1TaggedObjectParser ParseImplicitBaseTagged(int baseTagClass, int baseTagNo) =>
            new DLTaggedObjectParser(baseTagClass, baseTagNo, m_constructed, m_parser);

        public override Asn1Object ToAsn1Object()
        {
            try
            {
                return m_parser.LoadTaggedDL(TagClass, TagNo, m_constructed);
            }
            catch (IOException e)
            {
                throw new Asn1ParsingException(e.Message);
            }
        }

        private Asn1StreamParser CheckConstructed()
        {
            if (!m_constructed)
                throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");

            return m_parser;
        }
    }
}
