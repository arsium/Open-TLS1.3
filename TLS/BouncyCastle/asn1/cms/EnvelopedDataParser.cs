#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
	* Produce an object suitable for an Asn1OutputStream.
	* <pre>
	* EnvelopedData ::= SEQUENCE {
	*     version CMSVersion,
	*     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	*     recipientInfos RecipientInfos,
	*     encryptedContentInfo EncryptedContentInfo,
	*     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
	* }
	* </pre>
	*/
    public class EnvelopedDataParser
    {
        private Asn1SequenceParser _seq;
        private DerInteger _version;
        private IAsn1Convertible _nextObject;
        private bool _originatorInfoCalled;

        public EnvelopedDataParser(
            Asn1SequenceParser seq)
        {
            this._seq = seq;
            this._version = (DerInteger)seq.ReadObject();
        }

        public DerInteger Version
        {
            get { return _version; }
        }

        public OriginatorInfo GetOriginatorInfo()
        {
            _originatorInfoCalled = true;

            if (_nextObject == null)
            {
                _nextObject = _seq.ReadObject();
            }

            if (_nextObject is Asn1TaggedObjectParser o)
            {
                if (o.HasContextTag(0))
                {
                    Asn1SequenceParser originatorInfo = (Asn1SequenceParser)o.ParseBaseUniversal(false, Asn1Tags.Sequence);
                    _nextObject = null;
                    return OriginatorInfo.GetInstance(originatorInfo.ToAsn1Object());
                }
            }

            return null;
        }

        public Asn1SetParser GetRecipientInfos()
        {
            if (!_originatorInfoCalled)
            {
                GetOriginatorInfo();
            }

            if (_nextObject == null)
            {
                _nextObject = _seq.ReadObject();
            }

            Asn1SetParser recipientInfos = (Asn1SetParser)_nextObject;
            _nextObject = null;
            return recipientInfos;
        }

        public EncryptedContentInfoParser GetEncryptedContentInfo()
        {
            if (_nextObject == null)
            {
                _nextObject = _seq.ReadObject();
            }

            if (_nextObject != null)
            {
                Asn1SequenceParser o = (Asn1SequenceParser)_nextObject;
                _nextObject = null;
                return new EncryptedContentInfoParser(o);
            }

            return null;
        }

        public Asn1SetParser GetUnprotectedAttrs()
        {
            if (_nextObject == null)
            {
                _nextObject = _seq.ReadObject();
            }

            if (_nextObject != null)
            {
                Asn1TaggedObjectParser o = (Asn1TaggedObjectParser)_nextObject;
                _nextObject = null;
                return (Asn1SetParser)Asn1Utilities.ParseContextBaseUniversal(o, 1, false, Asn1Tags.SetOf);
            }

            return null;
        }
    }
}
