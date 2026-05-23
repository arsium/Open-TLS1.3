#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECNamedDomainParameters
        : ECDomainParameters
    {
        public static ECNamedDomainParameters LookupOid(DerObjectIdentifier oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            var x9 = ECUtilities.FindECCurveByOid(oid) ??
                throw new ArgumentException("OID is not a valid public key parameter set", nameof(oid));

            return new ECNamedDomainParameters(oid, x9);
        }

        private readonly DerObjectIdentifier m_name;

        public ECNamedDomainParameters(DerObjectIdentifier name, ECDomainParameters dp)
            : base(dp)
        {
            m_name = name;
        }

        public ECNamedDomainParameters(DerObjectIdentifier name, X9ECParameters x9)
            : base(x9)
        {
            m_name = name;
        }

        public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint g, BigInteger n)
            : base(curve, g, n)
        {
            m_name = name;
        }

        public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint g, BigInteger n, BigInteger h)
            : base(curve, g, n, h)
        {
            m_name = name;
        }

        public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint g, BigInteger n, BigInteger h,
            byte[] seed)
            : base(curve, g, n, h, seed)
        {
            m_name = name;
        }

        public DerObjectIdentifier Name => m_name;

        public override X962Parameters ToX962Parameters() => new X962Parameters(Name);
    }
}
