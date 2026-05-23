#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	/**
	 * Interface to SP800-90A deterministic random bit generators.
	 */
	public interface ISP80090Drbg
	{
	    /**
	     * Return the block size of the DRBG.
	     *
	     * @return the block size (in bits) produced by each round of the DRBG.
	     */
		int BlockSize { get; }

        /**
	     * Populate a passed in array with random data.
	     *
	     * @param output output array for generated bits.
	     * @param additionalInput additional input to be added to the DRBG in this step.
	     * @param predictionResistant true if a reseed should be forced, false otherwise.
	     *
	     * @return number of bits generated, -1 if a reseed required.
	     */
        int Generate(byte[] output, int outputOff, int outputLen, byte[] additionalInput, bool predictionResistant);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        int Generate(Span<byte> output, bool predictionResistant);

        int GenerateWithInput(Span<byte> output, ReadOnlySpan<byte> additionalInput, bool predictionResistant);
#endif

        /**
	     * Reseed the DRBG.
	     *
	     * @param additionalInput additional input to be added to the DRBG in this step.
	     */
        void Reseed(byte[] additionalInput);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void Reseed(ReadOnlySpan<byte> additionalInput);
#endif
    }
}
