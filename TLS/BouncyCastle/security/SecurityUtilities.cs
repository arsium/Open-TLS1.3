#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿namespace Org.BouncyCastle.Security
{
    internal static class SecurityUtilities
    {
        /*
         * These three got introduced in some messages as a result of a typo in an early document. We don't produce
         * anything using these OID values, but we'll read them.
         */
        internal static readonly string WrongAes128 = "2.16.840.1.101.3.4.2";
        internal static readonly string WrongAes192 = "2.16.840.1.101.3.4.22";
        internal static readonly string WrongAes256 = "2.16.840.1.101.3.4.42";
    }
}
