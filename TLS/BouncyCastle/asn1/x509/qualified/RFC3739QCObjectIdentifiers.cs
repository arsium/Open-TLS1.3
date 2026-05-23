#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    // TODO[api] Make static
    public sealed class Rfc3739QCObjectIdentifiers
    {
		private Rfc3739QCObjectIdentifiers()
		{
		}

		//
        // base id
        //
        public static readonly DerObjectIdentifier IdQcs = X509ObjectIdentifiers.IdPkix.Branch("11");

        public static readonly DerObjectIdentifier IdQcsPkixQCSyntaxV1 = IdQcs.Branch("1");
        public static readonly DerObjectIdentifier IdQcsPkixQCSyntaxV2 = IdQcs.Branch("2");
    }
}
