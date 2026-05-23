#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1DigestFactory
        : IDigestFactory
    {
        public static Asn1DigestFactory Get(DerObjectIdentifier oid) =>
            new Asn1DigestFactory(DigestUtilities.GetDigest(oid), oid);

        public static Asn1DigestFactory Get(string mechanism) => Get(DigestUtilities.GetObjectIdentifier(mechanism));

        private readonly IDigest m_digest;
        private readonly DerObjectIdentifier m_oid;

        public Asn1DigestFactory(IDigest digest, DerObjectIdentifier oid)
        {
            m_digest = digest;
            m_oid = oid;
        }

        public virtual object AlgorithmDetails => new AlgorithmIdentifier(m_oid);

        public virtual int DigestLength => m_digest.GetDigestSize();

        public virtual IStreamCalculator<IBlockResult> CreateCalculator() => new DefaultDigestCalculator(m_digest);
    }
}
