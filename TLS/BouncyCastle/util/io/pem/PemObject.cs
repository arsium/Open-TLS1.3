#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
	public class PemObject
		: PemObjectGenerator
	{
		private readonly string m_type;
		private readonly IList<PemHeader> m_headers;
		private readonly byte[] m_content;

		public PemObject(string type, byte[] content)
			: this(type, new List<PemHeader>(), content)
		{
		}

		public PemObject(string type, IList<PemHeader> headers, byte[] content)
		{
			m_type = type;
            m_headers = new List<PemHeader>(headers);
			m_content = content;
		}

		public string Type
		{
			get { return m_type; }
		}

		public IList<PemHeader> Headers
		{
			get { return m_headers; }
		}

		public byte[] Content
		{
			get { return m_content; }
		}

		public PemObject Generate()
		{
			return this;
		}
	}
}
