#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.SlhDsa;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class SlhDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private SlhDsaParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((SlhDsaKeyGenerationParameters)parameters).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var engine = m_parameters.ParameterSet.GetEngine();

            byte[] skSeed = SecRand(engine.N);
            byte[] skPrf = SecRand(engine.N);
            byte[] pkSeed = SecRand(engine.N);

            SK sk = new SK(skSeed, skPrf);

            engine.Init(pkSeed);

            // TODO
            PK pk = new PK(pkSeed, new HT(engine, sk.Seed, pkSeed).HTPubKey);

            return new AsymmetricCipherKeyPair(
                new SlhDsaPublicKeyParameters(m_parameters, pk),
                new SlhDsaPrivateKeyParameters(m_parameters, sk, pk));
        }

        private byte[] SecRand(int n) => SecureRandom.GetNextBytes(m_random, n);
    }
}
