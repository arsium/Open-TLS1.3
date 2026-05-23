#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Prng
{
	/// <remarks>Generic interface for objects generating random bytes.</remarks>
	public interface IRandomGenerator
	{
		/// <summary>Add more seed material to the generator.</summary>
		/// <param name="seed">A byte array to be mixed into the generator's state.</param>
		void AddSeedMaterial(byte[] seed);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void AddSeedMaterial(ReadOnlySpan<byte> seed);
#endif

        /// <summary>Add more seed material to the generator.</summary>
        /// <param name="seed">A long value to be mixed into the generator's state.</param>
        void AddSeedMaterial(long seed);

		/// <summary>Fill byte array with random values.</summary>
		/// <param name="bytes">Array to be filled.</param>
		void NextBytes(byte[] bytes);

		/// <summary>Fill byte array with random values.</summary>
		/// <param name="bytes">Array to receive bytes.</param>
		/// <param name="start">Index to start filling at.</param>
		/// <param name="len">Length of segment to fill.</param>
		void NextBytes(byte[] bytes, int start, int len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		void NextBytes(Span<byte> bytes);
#endif
	}
}
