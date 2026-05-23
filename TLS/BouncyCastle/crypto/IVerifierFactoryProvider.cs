#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a provider to support the dynamic creation of signature verifiers.
    /// </summary>
    public interface IVerifierFactoryProvider
	{
        /// <summary>
        /// Return a signature verfier for signature algorithm described in the passed in algorithm details object.
        /// </summary>
        /// <param name="algorithmDetails">The details of the signature algorithm verification is required for.</param>
        /// <returns>A new signature verifier.</returns>
		IVerifierFactory CreateVerifierFactory (object algorithmDetails);
	}
}

