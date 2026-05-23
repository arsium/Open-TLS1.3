#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * OOBCert ::= CMPCertificate
     */
    // TODO[api] Remove and just use CmpCertificate
    public class OobCert
        : CmpCertificate
    {
        public static new OobCert GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static new OobCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static new OobCert GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OobCert oobCert)
                return oobCert;

            X509CertificateStructure x509v3PKCert = X509CertificateStructure.GetOptional(element);
            if (x509v3PKCert != null)
                return new OobCert(x509v3PKCert);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null && taggedObject.HasContextTag() && taggedObject.IsExplicit())
            {
#pragma warning disable CS0618 // Type or member is obsolete
                return new OobCert(taggedObject.TagNo, taggedObject.GetBaseObject());
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return null;
        }

        public static new OobCert GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        [Obsolete("Use constructor from Asn1TaggedObject instead")]
        public OobCert(int type, Asn1Encodable otherCert)
            : base(type, otherCert)
        {
        }

        public OobCert(X509CertificateStructure x509v3PKCert)
            : base(x509v3PKCert)
        {
        }
    }
}
