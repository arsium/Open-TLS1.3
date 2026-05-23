#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     *    KemCiphertextInfo ::= SEQUENCE {
     *      kem              AlgorithmIdentifier{KEM-ALGORITHM, {...}},
     *      ct               OCTET STRING
     *    }
     * </pre>
     */
    public class KemCiphertextInfo
        : Asn1Encodable
    {
        public static KemCiphertextInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemCiphertextInfo kemCiphertextInfo)
                return kemCiphertextInfo;
            return new KemCiphertextInfo(Asn1Sequence.GetInstance(obj));
        }

        public static KemCiphertextInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemCiphertextInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static KemCiphertextInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemCiphertextInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_kem;
        private readonly Asn1OctetString m_ct;

        private KemCiphertextInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_kem = AlgorithmIdentifier.GetInstance(seq[0]);
            m_ct = Asn1OctetString.GetInstance(seq[1]);
        }

        public KemCiphertextInfo(AlgorithmIdentifier kem, Asn1OctetString ct)
        {
            m_kem = kem ?? throw new ArgumentNullException(nameof(kem));
            m_ct = ct ?? throw new ArgumentNullException(nameof(ct));
        }

        public virtual AlgorithmIdentifier Kem => m_kem;

        public virtual Asn1OctetString Ct => m_ct;

        /**
         * <pre>
         *    KemCiphertextInfo ::= SEQUENCE {
         *      kem              AlgorithmIdentifier{KEM-ALGORITHM, {...}},
         *      ct               OCTET STRING
         *    }
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_kem, m_ct);
    }
}
