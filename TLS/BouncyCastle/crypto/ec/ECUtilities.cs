#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;

namespace Org.BouncyCastle.Crypto.EC
{
    internal static class ECUtilities
    {
        internal static X9ECParameters FindECCurveByName(string name) =>
            CustomNamedCurves.GetByName(name) ?? ECNamedCurveTable.GetByName(name);

        internal static X9ECParametersHolder FindECCurveByNameLazy(string name) =>
            CustomNamedCurves.GetByNameLazy(name) ?? ECNamedCurveTable.GetByNameLazy(name);

        internal static X9ECParameters FindECCurveByOid(DerObjectIdentifier oid) =>
            CustomNamedCurves.GetByOid(oid) ?? ECNamedCurveTable.GetByOid(oid);

        internal static X9ECParametersHolder FindECCurveByOidLazy(DerObjectIdentifier oid) =>
            CustomNamedCurves.GetByOidLazy(oid) ?? ECNamedCurveTable.GetByOidLazy(oid);

        internal static DerObjectIdentifier FindECCurveOid(string name) =>
            CustomNamedCurves.GetOid(name) ?? ECNamedCurveTable.GetOid(name);
    }
}
