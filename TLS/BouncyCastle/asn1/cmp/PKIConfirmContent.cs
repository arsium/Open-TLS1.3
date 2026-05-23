#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  PKIConfirmContent ::= NULL
     */
    public class PkiConfirmContent
		: Asn1Encodable
	{
		public static PkiConfirmContent GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is PkiConfirmContent pkiConfirmContent)
				return pkiConfirmContent;
			return new PkiConfirmContent(Asn1Null.GetInstance(obj));
		}

        public static PkiConfirmContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiConfirmContent(Asn1Null.GetInstance(taggedObject, declaredExplicit));

        public static PkiConfirmContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiConfirmContent(Asn1Null.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Null m_val;

        public PkiConfirmContent()
            : this(DerNull.Instance)
        {
        }

        private PkiConfirmContent(Asn1Null val)
        {
            m_val = val;
        }

		/**
		 * <pre>
		 * PkiConfirmContent ::= NULL
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object() => m_val;
	}
}
