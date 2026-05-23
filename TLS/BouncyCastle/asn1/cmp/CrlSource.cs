#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * GenMsg:    {id-it TBD1}, SEQUENCE SIZE (1..MAX) OF CRLStatus
     * GenRep:    {id-it TBD2}, SEQUENCE SIZE (1..MAX) OF
     * CertificateList  |  &lt; absent &gt;
     * <p>
     * CRLSource ::= CHOICE {
     * dpn          [0] DistributionPointName,
     * issuer       [1] GeneralNames }
     * </p>
     */
    public class CrlSource
        : Asn1Encodable, IAsn1Choice
    {
        public static CrlSource GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static CrlSource GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static CrlSource GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CrlSource crlSource)
                return crlSource;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new CrlSource(dpn: DistributionPointName.GetTagged(taggedObject, true), issuer: null);

                if (taggedObject.HasContextTag(1))
                    return new CrlSource(dpn: null, issuer: GeneralNames.GetTagged(taggedObject, true));
            }

            return null;
        }

        public static CrlSource GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly DistributionPointName m_dpn;
        private readonly GeneralNames m_issuer;

        public CrlSource(DistributionPointName dpn, GeneralNames issuer)
        {
            if ((dpn == null) == (issuer == null))
                throw new ArgumentException("either dpn or issuer must be set");

            m_dpn = dpn;
            m_issuer = issuer;
        }

        public virtual DistributionPointName Dpn => m_dpn;

        public virtual GeneralNames Issuer => m_issuer;

        public override Asn1Object ToAsn1Object()
        {
            if (m_dpn != null)
                return new DerTaggedObject(true, 0, m_dpn);
            if (m_issuer != null)
                return new DerTaggedObject(true, 1, m_issuer);
            throw new InvalidOperationException();
        }
    }
}
