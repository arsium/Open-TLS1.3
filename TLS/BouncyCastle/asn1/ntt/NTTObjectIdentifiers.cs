#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Asn1.Ntt
{
    /// <summary>From RFC 3657</summary>
    // TODO[api] Make static
    public abstract class NttObjectIdentifiers
	{
		public static readonly DerObjectIdentifier IdCamellia128Cbc = new DerObjectIdentifier("1.2.392.200011.61.1.1.1.2");
		public static readonly DerObjectIdentifier IdCamellia192Cbc = new DerObjectIdentifier("1.2.392.200011.61.1.1.1.3");
		public static readonly DerObjectIdentifier IdCamellia256Cbc = new DerObjectIdentifier("1.2.392.200011.61.1.1.1.4");

		public static readonly DerObjectIdentifier IdCamellia128Wrap = new DerObjectIdentifier("1.2.392.200011.61.1.1.3.2");
		public static readonly DerObjectIdentifier IdCamellia192Wrap = new DerObjectIdentifier("1.2.392.200011.61.1.1.3.3");
		public static readonly DerObjectIdentifier IdCamellia256Wrap = new DerObjectIdentifier("1.2.392.200011.61.1.1.3.4");
	}
}
