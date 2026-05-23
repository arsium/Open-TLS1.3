#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include a source of randomness (SecureRandom).
    /// </summary>
    public class ParametersWithRandom
		: ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
		private readonly SecureRandom m_random;

        /// <summary>
        /// Constructor using the default secure random from <see cref="CryptoServicesRegistrar"/>.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        public ParametersWithRandom(ICipherParameters parameters)
            : this(parameters, CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="random">The source of randomness.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or <paramref name="random"/> is
        /// null.</exception>
        public ParametersWithRandom(ICipherParameters parameters, SecureRandom random)
        {
			m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            m_random = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>
        /// Return the base parameters associated with this randomness.
        /// </summary>
        /// <returns>The parameters wrapped by this source of randomness.</returns>
        public ICipherParameters Parameters => m_parameters;

        /// <summary>
        /// Return the source of randomness.
        /// </summary>
        /// <returns>The source of randomness.</returns>
        public SecureRandom Random => m_random;
    }
}
