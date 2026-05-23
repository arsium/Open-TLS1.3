#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertResponse
		: Asn1Encodable
	{
        public static CertResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertResponse certResponse)
                return certResponse;
            return new CertResponse(Asn1Sequence.GetInstance(obj));
        }

        public static CertResponse GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertResponse(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_certReqId;
		private readonly PkiStatusInfo m_status;
		private readonly CertifiedKeyPair m_certifiedKeyPair;
		private readonly Asn1OctetString m_rspInfo;

		private CertResponse(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certReqId = DerInteger.GetInstance(seq[pos++]);
            m_status = PkiStatusInfo.GetInstance(seq[pos++]);
            m_certifiedKeyPair = Asn1Utilities.ReadOptional(seq, ref pos, CertifiedKeyPair.GetOptional);
            m_rspInfo = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CertResponse(DerInteger certReqId, PkiStatusInfo status)
			: this(certReqId, status, null, null)
		{
		}

        public CertResponse(DerInteger certReqId, PkiStatusInfo status, CertifiedKeyPair certifiedKeyPair,
            Asn1OctetString rspInfo)
        {
			m_certReqId = certReqId ?? throw new ArgumentNullException(nameof(certReqId));
			m_status = status ?? throw new ArgumentNullException(nameof(status));
            m_certifiedKeyPair = certifiedKeyPair;
			m_rspInfo = rspInfo;
		}

		public virtual DerInteger CertReqID => m_certReqId;

		public virtual PkiStatusInfo Status => m_status;

		public virtual CertifiedKeyPair CertifiedKeyPair => m_certifiedKeyPair;

		public virtual Asn1OctetString RspInfo => m_rspInfo;

		/**
		 * <pre>
		 * CertResponse ::= SEQUENCE {
		 *                            certReqId           INTEGER,
		 *                            -- to match this response with corresponding request (a value
		 *                            -- of -1 is to be used if certReqId is not specified in the
		 *                            -- corresponding request)
		 *                            status              PKIStatusInfo,
		 *                            certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
		 *                            rspInfo             OCTET STRING        OPTIONAL
		 *                            -- analogous to the id-regInfo-utf8Pairs string defined
		 *                            -- for regInfo in CertReqMsg [CRMF]
		 *             }
		 * </pre> 
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(4);
			v.Add(m_certReqId, m_status);
			v.AddOptional(m_certifiedKeyPair, m_rspInfo);
			return new DerSequence(v);
		}
	}
}
