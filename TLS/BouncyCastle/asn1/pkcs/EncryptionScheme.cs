#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    // TODO[api] This is not supposed to be a separate type; remove and use AlgorithmIdentifier
    public class EncryptionScheme
        : AlgorithmIdentifier
    {
        public new static EncryptionScheme GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptionScheme encryptionScheme)
                return encryptionScheme;
            return new EncryptionScheme(Asn1Sequence.GetInstance(obj));
        }

        public new static EncryptionScheme GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptionScheme(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public new static EncryptionScheme GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptionScheme(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public EncryptionScheme(
            DerObjectIdentifier	objectID)
            : base(objectID)
        {
        }

        public EncryptionScheme(
            DerObjectIdentifier	objectID,
            Asn1Encodable		parameters)
			: base(objectID, parameters)
		{
		}

		internal EncryptionScheme(
			Asn1Sequence seq)
			: this((DerObjectIdentifier)seq[0], seq[1])
        {
        }

		public Asn1Object Asn1Object
		{
			get { return Parameters.ToAsn1Object(); }
		}

		public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(Algorithm, Parameters);
        }
    }
}
