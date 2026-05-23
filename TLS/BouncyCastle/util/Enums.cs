#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Utilities
{
    internal static class Enums
    {
        internal static TEnum[] GetEnumValues<TEnum>()
            where TEnum : struct, Enum
        {
#if NET5_0_OR_GREATER
            return Enum.GetValues<TEnum>();
#else
            return (TEnum[])Enum.GetValues(typeof(TEnum));
#endif
        }

        internal static TEnum GetArbitraryValue<TEnum>()
            where TEnum : struct, Enum
        {
            TEnum[] values = GetEnumValues<TEnum>();
            int pos = (int)(DateTimeUtilities.CurrentUnixMs() & int.MaxValue) % values.Length;
            return values[pos];
        }

        internal static bool TryGetEnumValue<TEnum>(string s, out TEnum result)
            where TEnum : struct, Enum
        {
            // We only want to parse single named constants
            if (s.Length > 0 && char.IsLetter(s[0]) && s.IndexOf(',') < 0)
            {
                s = s.Replace('-', '_');
                s = s.Replace('/', '_');

                return Enum.TryParse<TEnum>(s, out result);
            }

            result = default(TEnum);
            return false;
        }
    }
}
