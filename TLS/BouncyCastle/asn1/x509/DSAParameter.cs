#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    public class DsaParameter
        : Asn1Encodable
    {
        public static DsaParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DsaParameter dsaParameter)
                return dsaParameter;
            return new DsaParameter(Asn1Sequence.GetInstance(obj));
        }

        public static DsaParameter GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new DsaParameter(Asn1Sequence.GetInstance(obj, explicitly));

        public static DsaParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DsaParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_p, m_q, m_g;

        public DsaParameter(BigInteger p, BigInteger q, BigInteger g)
        {
            m_p = new DerInteger(p);
            m_q = new DerInteger(q);
            m_g = new DerInteger(g);
        }

        private DsaParameter(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_p = DerInteger.GetInstance(seq[0]);
			m_q = DerInteger.GetInstance(seq[1]);
			m_g = DerInteger.GetInstance(seq[2]);
        }

		public BigInteger P => m_p.PositiveValue;

		public BigInteger Q => m_q.PositiveValue;

		public BigInteger G => m_g.PositiveValue;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_p, m_q, m_g);
    }
}
