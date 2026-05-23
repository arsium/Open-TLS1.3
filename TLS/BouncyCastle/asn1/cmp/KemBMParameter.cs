#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     *  KemBMParameter ::= SEQUENCE {
     *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
     *      len              INTEGER (1..MAX),
     *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *   }
     * </pre>
     */
    public class KemBMParameter
        : Asn1Encodable
    {
        public static KemBMParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemBMParameter kemBMParameter)
                return kemBMParameter;
            return new KemBMParameter(Asn1Sequence.GetInstance(obj));
        }

        public static KemBMParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemBMParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static KemBMParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemBMParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_kdf;
        private readonly DerInteger m_len;
        private readonly AlgorithmIdentifier m_mac;

        private KemBMParameter(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_kdf = AlgorithmIdentifier.GetInstance(seq[0]);
            m_len = DerInteger.GetInstance(seq[1]);
            m_mac = AlgorithmIdentifier.GetInstance(seq[2]);
        }

        public KemBMParameter(AlgorithmIdentifier kdf, DerInteger len, AlgorithmIdentifier mac)
        {
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
            m_len = len ?? throw new ArgumentNullException(nameof(len));
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        public KemBMParameter(AlgorithmIdentifier kdf, long len, AlgorithmIdentifier mac)
            : this(kdf, DerInteger.ValueOf(len), mac)
        {
        }

        public virtual AlgorithmIdentifier Kdf => m_kdf;

        public virtual DerInteger Len => m_len;

        public virtual AlgorithmIdentifier Mac => m_mac;

        /**
         * <pre>
         *  KemBMParameter ::= SEQUENCE {
         *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
         *      len              INTEGER (1..MAX),
         *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
         *    }
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_kdf, m_len, m_mac);
    }
}
