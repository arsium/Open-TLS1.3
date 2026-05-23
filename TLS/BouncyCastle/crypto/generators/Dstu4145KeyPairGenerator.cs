#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Generators
{
    // TODO[api] Could just subclass ECKeyPairGenerator except that GenerateKeyPair is not marked virtual there
    public class Dstu4145KeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private readonly ECKeyPairGenerator m_inner = new ECKeyPairGenerator();

        public virtual void Init(KeyGenerationParameters parameters) => m_inner.Init(parameters);

        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var keyPair = m_inner.GenerateKeyPair();

            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            var privateKey = (ECPrivateKeyParameters)keyPair.Private;

            publicKey = new ECPublicKeyParameters(publicKey.AlgorithmName, publicKey.Q.Negate(), publicKey.Parameters);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
