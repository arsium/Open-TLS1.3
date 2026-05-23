#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECGost3410Parameters
        : ECNamedDomainParameters
    {
        private readonly DerObjectIdentifier m_publicKeyParamSet;
        private readonly DerObjectIdentifier m_digestParamSet;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        public ECGost3410Parameters(ECNamedDomainParameters dp, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
            : base(dp.Name, dp.Curve, dp.G, dp.N, dp.H, dp.GetSeed())
        {
            m_publicKeyParamSet = publicKeyParamSet;
            m_digestParamSet = digestParamSet;
            m_encryptionParamSet = encryptionParamSet;
        }

        public ECGost3410Parameters(ECDomainParameters dp, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
            : base(dp is ECNamedDomainParameters ndp ? ndp.Name : publicKeyParamSet, dp.Curve, dp.G, dp.N, dp.H,
                  dp.GetSeed())
        {
            m_publicKeyParamSet = publicKeyParamSet;
            m_digestParamSet = digestParamSet;
            m_encryptionParamSet = encryptionParamSet;
        }

        public DerObjectIdentifier PublicKeyParamSet => m_publicKeyParamSet;

        public DerObjectIdentifier DigestParamSet => m_digestParamSet;

        public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;
    }
}
