#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AttCertValidityPeriod
        : Asn1Encodable
    {
        public static AttCertValidityPeriod GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttCertValidityPeriod attCertValidityPeriod)
                return attCertValidityPeriod;
            return new AttCertValidityPeriod(Asn1Sequence.GetInstance(obj));
        }

        public static AttCertValidityPeriod GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new AttCertValidityPeriod(Asn1Sequence.GetInstance(obj, explicitly));

        public static AttCertValidityPeriod GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttCertValidityPeriod(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1GeneralizedTime m_notBeforeTime;
        private readonly Asn1GeneralizedTime m_notAfterTime;

        private AttCertValidityPeriod(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_notBeforeTime = Asn1GeneralizedTime.GetInstance(seq[0]);
			m_notAfterTime = Asn1GeneralizedTime.GetInstance(seq[1]);
        }

        public AttCertValidityPeriod(Asn1GeneralizedTime notBeforeTime, Asn1GeneralizedTime notAfterTime)
        {
            m_notBeforeTime = notBeforeTime ?? throw new ArgumentNullException(nameof(notBeforeTime));
            m_notAfterTime = notAfterTime ?? throw new ArgumentNullException(nameof(notAfterTime));
        }

        public Asn1GeneralizedTime NotBeforeTime => m_notBeforeTime;

        public Asn1GeneralizedTime NotAfterTime => m_notAfterTime;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  AttCertValidityPeriod  ::= Sequence {
         *       notBeforeTime  GeneralizedTime,
         *       notAfterTime   GeneralizedTime
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_notBeforeTime, m_notAfterTime);
    }
}
