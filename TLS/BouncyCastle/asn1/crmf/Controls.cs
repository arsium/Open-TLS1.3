#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class Controls
        : Asn1Encodable
    {
        public static Controls GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Controls controls)
                return controls;
            return new Controls(Asn1Sequence.GetInstance(obj));
        }

        public static Controls GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Controls(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Controls GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Controls controls)
                return controls;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Controls(asn1Sequence);

            return null;
        }

        public static Controls GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Controls(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private Controls(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public Controls(params AttributeTypeAndValue[] atvs)
        {
            m_content = new DerSequence(atvs);
        }

        public virtual AttributeTypeAndValue[] ToAttributeTypeAndValueArray() =>
            m_content.MapElements(AttributeTypeAndValue.GetInstance);

        /**
         * <pre>
         * Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
