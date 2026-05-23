#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a key unwrapper.
    /// </summary>
    public interface IKeyUnwrapper
    {
        /// <summary>
        /// The parameter set used to configure this key unwrapper.
        /// </summary>
        object AlgorithmDetails { get; }

        /// <summary>
        /// Unwrap the passed in data.
        /// </summary>
        /// <param name="cipherText">The array containing the data to be unwrapped.</param>
        /// <param name="offset">The offset into cipherText at which the unwrapped data starts.</param>
        /// <param name="length">The length of the data to be unwrapped.</param>
        /// <returns>an IBlockResult containing the unwrapped key data.</returns>
        IBlockResult Unwrap(byte[] cipherText, int offset, int length);
    }
}
