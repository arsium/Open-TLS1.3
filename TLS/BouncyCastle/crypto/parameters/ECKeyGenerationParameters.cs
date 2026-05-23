#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly ECDomainParameters m_domainParameters;

        public ECKeyGenerationParameters(ECDomainParameters domainParameters, SecureRandom random)
            : base(random, domainParameters.N.BitLength)
        {
            m_domainParameters = domainParameters;
        }

        public ECKeyGenerationParameters(DerObjectIdentifier publicKeyParamSet, SecureRandom random)
            : this(ECNamedDomainParameters.LookupOid(oid: publicKeyParamSet), random)
        {
        }

        public ECDomainParameters DomainParameters => m_domainParameters;

        public DerObjectIdentifier PublicKeyParamSet => (m_domainParameters as ECNamedDomainParameters)?.Name;
    }
}
