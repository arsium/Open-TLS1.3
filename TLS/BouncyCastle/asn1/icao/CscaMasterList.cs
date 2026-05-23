#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Icao
{
    /**
	 * The CscaMasterList object. This object can be wrapped in a
	 * CMSSignedData to be published in LDAP.
	 *
	 * <pre>
	 * CscaMasterList ::= SEQUENCE {
	 *   version                CscaMasterListVersion,
	 *   certList               SET OF Certificate }
	 *   
	 * CscaMasterListVersion :: INTEGER {v0(0)}
	 * </pre>
	 */
    public class CscaMasterList 
		: Asn1Encodable 
	{
        public static CscaMasterList GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CscaMasterList cscaMasterList)
                return cscaMasterList;
            return new CscaMasterList(Asn1Sequence.GetInstance(obj));
        }

        public static CscaMasterList GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CscaMasterList(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CscaMasterList GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CscaMasterList(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

		private readonly DerInteger m_version;
        private readonly X509CertificateStructure[] m_certList;

        private CscaMasterList(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_version = DerInteger.GetInstance(seq[0]);
			m_certList = Asn1Set.GetInstance(seq[1]).MapElements(X509CertificateStructure.GetInstance);
		}

		public CscaMasterList(X509CertificateStructure[] certStructs)
		{
			m_version = DerInteger.Zero;
			m_certList = CopyCertList(certStructs);
		}

		public virtual int Version => m_version.IntValueExact;

		public X509CertificateStructure[] GetCertStructs() => CopyCertList(m_certList);

		private static X509CertificateStructure[] CopyCertList(X509CertificateStructure[] orig) =>
			(X509CertificateStructure[])orig.Clone();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_version, new DerSet(m_certList));
	}
}
