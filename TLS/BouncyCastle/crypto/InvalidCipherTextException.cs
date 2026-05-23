#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
	 /// <summary>This exception is thrown whenever we find something we don't expect in a message.</summary>
    [Serializable]
    public class InvalidCipherTextException
		: CryptoException
    {
		public InvalidCipherTextException()
			: base()
		{
		}

		public InvalidCipherTextException(string message)
			: base(message)
		{
		}

		public InvalidCipherTextException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected InvalidCipherTextException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
