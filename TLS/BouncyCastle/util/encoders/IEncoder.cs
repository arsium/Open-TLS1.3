#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
	/**
	 * Encode and decode byte arrays (typically from binary to 7-bit ASCII
	 * encodings).
	 */
	public interface IEncoder
	{
		int Encode(byte[] data, int off, int length, Stream outStream);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		int Encode(ReadOnlySpan<byte> data, Stream outStream);
#endif

		int Decode(byte[] data, int off, int length, Stream outStream);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		int Decode(ReadOnlySpan<byte> data, Stream outStream);
#endif

		int DecodeString(string data, Stream outStream);
	}
}
