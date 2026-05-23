#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertReqMessages
        : Asn1Encodable
    {
        public static CertReqMessages GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertReqMessages certReqMessages)
                return certReqMessages;
            return new CertReqMessages(Asn1Sequence.GetInstance(obj));
        }

        public static CertReqMessages GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMessages(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertReqMessages GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMessages(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private CertReqMessages(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public CertReqMessages(CertReqMsg msg)
        {
            m_content = DerSequence.FromElement(msg);
        }

        public CertReqMessages(params CertReqMsg[] msgs)
        {
            m_content = new DerSequence(msgs);
        }

        public virtual CertReqMsg[] ToCertReqMsgArray() => m_content.MapElements(CertReqMsg.GetInstance);

        /**
         * <pre>
         * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
