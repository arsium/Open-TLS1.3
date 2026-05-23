#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Security.Certificates
{
    [Serializable]
    public class CertificateParsingException
		: CertificateException
	{
		public CertificateParsingException()
			: base()
		{
		}

		public CertificateParsingException(string message)
			: base(message)
		{
		}

		public CertificateParsingException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected CertificateParsingException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
