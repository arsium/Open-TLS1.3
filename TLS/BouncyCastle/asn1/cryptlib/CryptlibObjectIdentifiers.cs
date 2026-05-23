#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿namespace Org.BouncyCastle.Asn1.Cryptlib
{
    internal static class CryptlibObjectIdentifiers
    {
        internal static readonly DerObjectIdentifier cryptlib = new DerObjectIdentifier("1.3.6.1.4.1.3029");

        internal static readonly DerObjectIdentifier ecc = cryptlib.Branch("1.5");

        internal static readonly DerObjectIdentifier curvey25519 = ecc.Branch("1");
    }
}
