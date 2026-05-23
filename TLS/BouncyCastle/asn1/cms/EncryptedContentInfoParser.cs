#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
	/**
	* <pre>
	* EncryptedContentInfo ::= SEQUENCE {
	*     contentType ContentType,
	*     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
	*     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	* }
	* </pre>
	*/
	public class EncryptedContentInfoParser
	{
		private readonly DerObjectIdentifier m_contentType;
		private readonly AlgorithmIdentifier m_contentEncryptionAlgorithm;
		private readonly Asn1TaggedObjectParser	m_encryptedContent;

		public EncryptedContentInfoParser(Asn1SequenceParser seq)
		{
			m_contentType = (DerObjectIdentifier)seq.ReadObject();
			m_contentEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq.ReadObject().ToAsn1Object());
			m_encryptedContent = (Asn1TaggedObjectParser)seq.ReadObject();
		}

		public DerObjectIdentifier ContentType => m_contentType;

		public AlgorithmIdentifier ContentEncryptionAlgorithm => m_contentEncryptionAlgorithm;

		public IAsn1Convertible GetEncryptedContent(int tag)
		{
			return Asn1Utilities.ParseContextBaseUniversal(m_encryptedContent, 0, false, tag);
		}
	}
}
