#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1.EdEC
{
    /**
     * Edwards Elliptic Curve Object Identifiers (RFC 8410)
     */
    // TODO[api] Make static
    public abstract class EdECObjectIdentifiers
    {
        public static readonly DerObjectIdentifier id_edwards_curve_algs = new DerObjectIdentifier("1.3.101");

        public static readonly DerObjectIdentifier id_X25519 = id_edwards_curve_algs.Branch("110");
        public static readonly DerObjectIdentifier id_X448 = id_edwards_curve_algs.Branch("111");
        public static readonly DerObjectIdentifier id_Ed25519 = id_edwards_curve_algs.Branch("112");
        public static readonly DerObjectIdentifier id_Ed448 = id_edwards_curve_algs.Branch("113");
    }
}
