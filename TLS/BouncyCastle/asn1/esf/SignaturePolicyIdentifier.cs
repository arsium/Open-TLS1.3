#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// SignaturePolicyIdentifier ::= CHOICE {
    ///		SignaturePolicyId		SignaturePolicyId,
    ///		SignaturePolicyImplied	SignaturePolicyImplied
    /// }
    /// 
    /// SignaturePolicyImplied ::= NULL
    /// </code>
    /// </remarks>
    public class SignaturePolicyIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        public static SignaturePolicyIdentifier GetInstance(object obj) =>
            Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static SignaturePolicyIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static SignaturePolicyIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SignaturePolicyIdentifier signaturePolicyIdentifier)
                return signaturePolicyIdentifier;

            SignaturePolicyId signaturePolicyId = Asn1.Esf.SignaturePolicyId.GetOptional(element);
            if (signaturePolicyId != null)
                return new SignaturePolicyIdentifier(signaturePolicyId);

            Asn1Null asn1Null = Asn1Null.GetOptional(element);
            if (asn1Null != null)
                return new SignaturePolicyIdentifier();

            return null;
        }

        public static SignaturePolicyIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly SignaturePolicyId m_sigPolicy;

        public SignaturePolicyIdentifier()
        {
            m_sigPolicy = null;
        }

        public SignaturePolicyIdentifier(SignaturePolicyId signaturePolicyId)
        {
            m_sigPolicy = signaturePolicyId ?? throw new ArgumentNullException(nameof(signaturePolicyId));
        }

        public SignaturePolicyId SignaturePolicyId => m_sigPolicy;

        public override Asn1Object ToAsn1Object() => m_sigPolicy?.ToAsn1Object() ?? DerNull.Instance;
    }
}
