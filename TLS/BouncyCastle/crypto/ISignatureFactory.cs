#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for operators that serve as stream-based signature calculators.
    /// </summary>
    // TODO[api] Add 'out A' type parameter for AlgorithmDetails return type
    public interface ISignatureFactory
	{
        /// <summary>The algorithm details object for this calculator.</summary>
        object AlgorithmDetails { get; }

        /// <summary>
        /// Create a stream calculator for this signature calculator. The stream
        /// calculator is used for the actual operation of entering the data to be signed
        /// and producing the signature block.
        /// </summary>
        /// <returns>A calculator producing an IBlockResult with a signature in it.</returns>
        IStreamCalculator<IBlockResult> CreateCalculator();
    }
}
