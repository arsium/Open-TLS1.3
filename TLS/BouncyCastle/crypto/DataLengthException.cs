#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>This exception is thrown if a buffer that is meant to have output copied into it turns out to be too
	/// short, or if we've been given insufficient input.</summary>
	/// <remarks>
	/// In general this exception will get thrown rather than an <see cref="IndexOutOfRangeException"/>.
	/// </remarks>
	[Serializable]
    public class DataLengthException
		: CryptoException
	{
		public DataLengthException()
			: base()
		{
		}

		public DataLengthException(string message)
			: base(message)
		{
		}

		public DataLengthException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected DataLengthException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
