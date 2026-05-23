#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    // TODO[api] Make static
    public abstract class EtsiQCObjectIdentifiers
	{
        //
        // base id
        //
        public static readonly DerObjectIdentifier IdEtsiQcs = new DerObjectIdentifier("0.4.0.1862.1");

        public static readonly DerObjectIdentifier IdEtsiQcsQcCompliance = IdEtsiQcs.Branch("1");
        public static readonly DerObjectIdentifier IdEtsiQcsLimitValue = IdEtsiQcs.Branch("2");
        public static readonly DerObjectIdentifier IdEtsiQcsRetentionPeriod = IdEtsiQcs.Branch("3");
        public static readonly DerObjectIdentifier IdEtsiQcsQcSscd = IdEtsiQcs.Branch("4");
        public static readonly DerObjectIdentifier IdEtsiQcsQcCClegislation = IdEtsiQcs.Branch("7");
    }
}
