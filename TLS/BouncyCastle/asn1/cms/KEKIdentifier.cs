#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class KekIdentifier
        : Asn1Encodable
    {
        public static KekIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KekIdentifier kekIdentifier)
                return kekIdentifier;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KekIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KekIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_keyIdentifier;
        private readonly Asn1GeneralizedTime m_date;
        private readonly OtherKeyAttribute m_other;

        public KekIdentifier(byte[] keyIdentifier, Asn1GeneralizedTime date, OtherKeyAttribute other)
        {
            m_keyIdentifier = DerOctetString.FromContents(keyIdentifier);
            m_date = date;
            m_other = other;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KekIdentifier(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyIdentifier = Asn1OctetString.GetInstance(seq[pos++]);
            m_date = Asn1Utilities.ReadOptional(seq, ref pos, Asn1GeneralizedTime.GetOptional);
            m_other = Asn1Utilities.ReadOptional(seq, ref pos, OtherKeyAttribute.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1OctetString KeyIdentifier => m_keyIdentifier;

        public Asn1GeneralizedTime Date => m_date;

        public OtherKeyAttribute Other => m_other;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * KekIdentifier ::= Sequence {
         *     keyIdentifier OCTET STRING,
         *     date GeneralizedTime OPTIONAL,
         *     other OtherKeyAttribute OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_keyIdentifier);
			v.AddOptional(m_date, m_other);
			return new DerSequence(v);
        }
    }
}

