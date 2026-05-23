#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    public class MLKemKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private MLKemParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((MLKemKeyGenerationParameters)parameters).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            m_parameters.ParameterSet.Engine.GenerateKemKeyPair(m_random, out byte[] seed, out byte[] encoding);

            var privateKey = new MLKemPrivateKeyParameters(m_parameters, seed, encoding,
                preferredFormat: MLKemPrivateKeyParameters.Format.SeedAndEncoding);

            return new AsymmetricCipherKeyPair(privateKey.GetPublicKey(), privateKey);
        }
    }
}
