#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the CryptoInfos element defined in RFC 4998:
     * <p/>
     * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
     */
    public class CryptoInfos
        : Asn1Encodable
    {
        public static CryptoInfos GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CryptoInfos cryptoInfos)
                return cryptoInfos;
            return new CryptoInfos(Asn1Sequence.GetInstance(obj));
        }

        public static CryptoInfos GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CryptoInfos(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CryptoInfos GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CryptoInfos(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_attributes;

        private CryptoInfos(Asn1Sequence attributes)
        {
            m_attributes = attributes;
        }

        public CryptoInfos(Asn1.Cms.Attribute[] attrs)
        {
            m_attributes = DerSequence.FromElements(attrs);
        }

        public virtual Asn1.Cms.Attribute[] GetAttributes() => m_attributes.MapElements(Asn1.Cms.Attribute.GetInstance);

        public override Asn1Object ToAsn1Object() => m_attributes;
    }
}
