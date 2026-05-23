#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Asn1.X509.SigI
{
    /**
	 * Object Identifiers of SigI specifciation (German Signature Law
	 * Interoperability specification).
	 */
    // TODO[api] Make static
    public sealed class SigIObjectIdentifiers
	{
		private SigIObjectIdentifiers()
		{
		}

		public readonly static DerObjectIdentifier IdSigI = new DerObjectIdentifier("1.3.36.8");

		/**
		* Key purpose IDs for German SigI (Signature Interoperability
		* Specification)
		*/
		public readonly static DerObjectIdentifier IdSigIKP = IdSigI.Branch("2");

		/**
		* Certificate policy IDs for German SigI (Signature Interoperability
		* Specification)
		*/
		public readonly static DerObjectIdentifier IdSigICP = IdSigI.Branch("1");

		/**
		* Other Name IDs for German SigI (Signature Interoperability Specification)
		*/
		public readonly static DerObjectIdentifier IdSigION = IdSigI.Branch("4");

		/**
		* To be used for for the generation of directory service certificates.
		*/
		public static readonly DerObjectIdentifier IdSigIKPDirectoryService = IdSigIKP.Branch("1");

		/**
		* ID for PersonalData
		*/
		public static readonly DerObjectIdentifier IdSigIONPersonalData = IdSigION.Branch("1");

		/**
		* Certificate is conform to german signature law.
		*/
		public static readonly DerObjectIdentifier IdSigICPSigConform = IdSigICP.Branch("1");
	}
}
