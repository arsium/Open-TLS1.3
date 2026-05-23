#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    internal class Rfc4211Asn1Utilities
    {
        internal static OptionalValidity CheckValidityFieldPresent(OptionalValidity validity)
        {
            // RFC 4211 5: If validity is not omitted, then at least one of the sub-fields MUST be specified.
            if (validity != null &&
                validity.NotBefore == null &&
                validity.NotAfter == null)
            {
                throw new ArgumentException("At least one of the sub-fields MUST be specified", nameof(validity));
            }

            return validity;
        }
    }
}
