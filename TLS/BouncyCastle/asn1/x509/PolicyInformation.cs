#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class PolicyInformation
        : Asn1Encodable
    {
        public static PolicyInformation GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PolicyInformation policyInformation)
                return policyInformation;
            return new PolicyInformation(Asn1Sequence.GetInstance(obj));
        }

        public static PolicyInformation GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PolicyInformation(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PolicyInformation GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PolicyInformation(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_policyIdentifier;
        private readonly Asn1Sequence m_policyQualifiers;

        private PolicyInformation(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_policyIdentifier = DerObjectIdentifier.GetInstance(seq[0]);
            m_policyQualifiers = count < 2 ? null : Asn1Sequence.GetInstance(seq[1]);
        }

        public PolicyInformation(DerObjectIdentifier policyIdentifier)
            : this(policyIdentifier, null)
        {
        }

        public PolicyInformation(DerObjectIdentifier policyIdentifier, Asn1Sequence policyQualifiers)
        {
            m_policyIdentifier = policyIdentifier ?? throw new ArgumentNullException(nameof(policyIdentifier));
            m_policyQualifiers = policyQualifiers;
        }

        public DerObjectIdentifier PolicyIdentifier => m_policyIdentifier;

        public Asn1Sequence PolicyQualifiers => m_policyQualifiers;

		/*
         * PolicyInformation ::= Sequence {
         *      policyIdentifier   CertPolicyId,
         *      policyQualifiers   Sequence SIZE (1..MAX) OF
         *              PolicyQualifierInfo OPTIONAL }
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_policyQualifiers == null
                ?  new DerSequence(m_policyIdentifier)
                :  new DerSequence(m_policyIdentifier, m_policyQualifiers);
        }
    }
}
