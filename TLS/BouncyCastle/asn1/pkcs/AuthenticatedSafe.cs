#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class AuthenticatedSafe
        : Asn1Encodable
    {
        public static AuthenticatedSafe GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthenticatedSafe authenticatedSafe)
                return authenticatedSafe;
            return new AuthenticatedSafe(Asn1Sequence.GetInstance(obj));
        }

        public static AuthenticatedSafe GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedSafe(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static AuthenticatedSafe GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedSafe(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo[] m_info;
        private readonly bool m_isBer;

		private AuthenticatedSafe(Asn1Sequence seq)
        {
            m_info = seq.MapElements(ContentInfo.GetInstance);
            m_isBer = seq is BerSequence;
        }

		public AuthenticatedSafe(ContentInfo[] info)
        {
            m_info = Copy(info);
            m_isBer = true;
        }

        public ContentInfo[] GetContentInfo() => Copy(m_info);

        public override Asn1Object ToAsn1Object()
        {
            return m_isBer
                ?  new BerSequence(m_info)
                :  new DLSequence(m_info);
        }

        private static ContentInfo[] Copy(ContentInfo[] info) => (ContentInfo[])info.Clone();
    }
}
