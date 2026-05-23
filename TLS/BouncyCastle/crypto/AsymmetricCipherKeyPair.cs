#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>A holding class for public/private key parameter pairs.</summary>
    public class AsymmetricCipherKeyPair
    {
        private readonly AsymmetricKeyParameter m_publicParameter;
        private readonly AsymmetricKeyParameter m_privateParameter;

        /// <summary>Basic constructor.</summary>
        /// <param name="publicParameter">A public key parameters object.</param>
        /// <param name="privateParameter">The corresponding private key parameters.</param>
        public AsymmetricCipherKeyPair(AsymmetricKeyParameter publicParameter, AsymmetricKeyParameter privateParameter)
        {
            if (publicParameter == null)
                throw new ArgumentNullException(nameof(publicParameter));
            if (publicParameter.IsPrivate)
                throw new ArgumentException("Expected a public key", nameof(publicParameter));
            if (privateParameter == null)
                throw new ArgumentNullException(nameof(privateParameter));
            if (!privateParameter.IsPrivate)
                throw new ArgumentException("Expected a private key", nameof(privateParameter));

            m_publicParameter = publicParameter;
            m_privateParameter = privateParameter;
        }

        /// <summary>Return the public key parameters.</summary>
        public AsymmetricKeyParameter Public => m_publicParameter;

        /// <summary>Return the private key parameters.</summary>
        public AsymmetricKeyParameter Private => m_privateParameter;
    }
}
