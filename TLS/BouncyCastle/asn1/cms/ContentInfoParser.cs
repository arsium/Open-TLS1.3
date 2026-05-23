#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	/**
	* Produce an object suitable for an Asn1OutputStream.
	* <pre>
	* ContentInfo ::= SEQUENCE {
	*          contentType ContentType,
	*          content
	*          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
	* </pre>
	*/
	public class ContentInfoParser
	{
		private readonly DerObjectIdentifier m_contentType;
		private readonly Asn1TaggedObjectParser m_content;

		public ContentInfoParser(Asn1SequenceParser seq)
		{
			m_contentType = (DerObjectIdentifier)seq.ReadObject();
			m_content = (Asn1TaggedObjectParser)seq.ReadObject();
		}

		public DerObjectIdentifier ContentType => m_contentType;

		public IAsn1Convertible GetContent(int tag)
		{
			if (null == m_content)
				return null;

            // TODO[cms] Ideally we could enforce the claimed tag
            //return Asn1Utilities.ParseContextBaseUniversal(content, 0, true, tag);
            return Asn1Utilities.ParseExplicitContextBaseObject(m_content, 0);
        }
	}
}
