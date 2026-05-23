#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    // TODO[api] Make static
    public abstract class OcspObjectIdentifiers
    {
        public static readonly DerObjectIdentifier PkixOcsp = X509ObjectIdentifiers.IdADOcsp;

        public static readonly DerObjectIdentifier PkixOcspBasic = PkixOcsp.Branch("1");
        public static readonly DerObjectIdentifier PkixOcspNonce = PkixOcsp.Branch("2");
        public static readonly DerObjectIdentifier PkixOcspCrl = PkixOcsp.Branch("3");
        public static readonly DerObjectIdentifier PkixOcspResponse = PkixOcsp.Branch("4");
        public static readonly DerObjectIdentifier PkixOcspNocheck = PkixOcsp.Branch("5");
        public static readonly DerObjectIdentifier PkixOcspArchiveCutoff = PkixOcsp.Branch("6");
        public static readonly DerObjectIdentifier PkixOcspServiceLocator = PkixOcsp.Branch("7");
        public static readonly DerObjectIdentifier PkixPcspPrefSigSlgs = PkixOcsp.Branch("8");
        public static readonly DerObjectIdentifier PkixPcspExtendedRevoke = PkixOcsp.Branch("9");
    }
}
