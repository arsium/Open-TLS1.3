#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class SinglePubInfo
        : Asn1Encodable
    {
        public static SinglePubInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SinglePubInfo singlePubInfo)
                return singlePubInfo;
            return new SinglePubInfo(Asn1Sequence.GetInstance(obj));
        }

        public static SinglePubInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SinglePubInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SinglePubInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SinglePubInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_pubMethod;
        private readonly GeneralName m_pubLocation;

        private SinglePubInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_pubMethod = DerInteger.GetInstance(seq[pos++]);

            if (pos < count)
            {
                m_pubLocation = GeneralName.GetInstance(seq[pos++]);
            }

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual GeneralName PubLocation => m_pubLocation;

        /**
         * <pre>
         * SinglePubInfo ::= SEQUENCE {
         *        pubMethod    INTEGER {
         *           dontCare    (0),
         *           x500        (1),
         *           web         (2),
         *           ldap        (3) },
         *       pubLocation  GeneralName OPTIONAL }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_pubLocation == null
                ?  new DerSequence(m_pubMethod)
                :  new DerSequence(m_pubMethod, m_pubLocation);
        }
    }
}
