#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
	/**
	* RFC 3274 - CMS Compressed Data.
	* <pre>
	* CompressedData ::= SEQUENCE {
	*  version CMSVersion,
	*  compressionAlgorithm CompressionAlgorithmIdentifier,
	*  encapContentInfo EncapsulatedContentInfo
	* }
	* </pre>
	*/
	public class CompressedDataParser
	{
		private DerInteger			_version;
		private AlgorithmIdentifier	_compressionAlgorithm;
		private ContentInfoParser	_encapContentInfo;

		public CompressedDataParser(
			Asn1SequenceParser seq)
		{
			this._version = (DerInteger)seq.ReadObject();
			this._compressionAlgorithm = AlgorithmIdentifier.GetInstance(seq.ReadObject().ToAsn1Object());
			this._encapContentInfo = new ContentInfoParser((Asn1SequenceParser)seq.ReadObject());
		}

		public DerInteger Version
		{
			get { return _version; }
		}

		public AlgorithmIdentifier CompressionAlgorithmIdentifier
		{
			get { return _compressionAlgorithm; }
		}

		public ContentInfoParser GetEncapContentInfo()
		{
			return _encapContentInfo;
		}
	}
}
