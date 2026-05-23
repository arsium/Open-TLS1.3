#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Asn1.X509
{
    internal class Rfc5280Asn1Utilities
    {
        internal static DerGeneralizedTime CreateGeneralizedTime(DateTime dateTime) =>
            new DerGeneralizedTime(DateTimeUtilities.WithPrecisionSecond(dateTime));

        internal static DerUtcTime CreateUtcTime(DateTime dateTime) => new DerUtcTime(dateTime, 2049);
    }
}
