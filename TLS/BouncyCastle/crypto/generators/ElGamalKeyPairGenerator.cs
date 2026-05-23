#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * a ElGamal key pair generator.
     * <p>
     * This Generates keys consistent for use with ElGamal as described in
     * page 164 of "Handbook of Applied Cryptography".</p>
     */
    // TODO[api] sealed
    public class ElGamalKeyPairGenerator
		: IAsymmetricCipherKeyPairGenerator
    {
        private ElGamalKeyGenerationParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_parameters = (ElGamalKeyGenerationParameters)parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
			ElGamalParameters egp = m_parameters.Parameters;
			DHParameters dhp = new DHParameters(egp.P, egp.G, null, 0, egp.L);

			BigInteger x = DHKeyGeneratorHelper.CalculatePrivate(dhp, m_parameters.Random);
			BigInteger y = DHKeyGeneratorHelper.CalculatePublic(dhp, x);

			return new AsymmetricCipherKeyPair(
                new ElGamalPublicKeyParameters(y, egp),
                new ElGamalPrivateKeyParameters(x, egp));
        }
    }
}
