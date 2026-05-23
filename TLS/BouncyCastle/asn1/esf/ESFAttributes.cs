#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Esf
{
	// TODO[api] Make static
    public abstract class EsfAttributes
    {
        public static readonly DerObjectIdentifier SigPolicyId = PkcsObjectIdentifiers.IdAAEtsSigPolicyID;
        public static readonly DerObjectIdentifier CommitmentType = PkcsObjectIdentifiers.IdAAEtsCommitmentType;
        public static readonly DerObjectIdentifier SignerLocation = PkcsObjectIdentifiers.IdAAEtsSignerLocation;
		public static readonly DerObjectIdentifier SignerAttr = PkcsObjectIdentifiers.IdAAEtsSignerAttr;
		public static readonly DerObjectIdentifier OtherSigCert = PkcsObjectIdentifiers.IdAAEtsOtherSigCert;
		public static readonly DerObjectIdentifier ContentTimestamp = PkcsObjectIdentifiers.IdAAEtsContentTimestamp;
		public static readonly DerObjectIdentifier CertificateRefs = PkcsObjectIdentifiers.IdAAEtsCertificateRefs;
		public static readonly DerObjectIdentifier RevocationRefs = PkcsObjectIdentifiers.IdAAEtsRevocationRefs;
		public static readonly DerObjectIdentifier CertValues = PkcsObjectIdentifiers.IdAAEtsCertValues;
		public static readonly DerObjectIdentifier RevocationValues = PkcsObjectIdentifiers.IdAAEtsRevocationValues;
		public static readonly DerObjectIdentifier EscTimeStamp = PkcsObjectIdentifiers.IdAAEtsEscTimeStamp;
		public static readonly DerObjectIdentifier CertCrlTimestamp = PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp;
		public static readonly DerObjectIdentifier ArchiveTimestamp = PkcsObjectIdentifiers.IdAAEtsArchiveTimestamp;
		public static readonly DerObjectIdentifier ArchiveTimestampV2 = PkcsObjectIdentifiers.IdAAEtsArchiveTimestampV2;
	}
}
