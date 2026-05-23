#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
#endif

namespace Org.BouncyCastle.Runtime.Intrinsics
{
    internal static class Vector
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsPacked =>
            Unsafe.SizeOf<Vector64<byte>>() == 8 &&
            Unsafe.SizeOf<Vector128<byte>>() == 16 &&
            Unsafe.SizeOf<Vector256<byte>>() == 32;

        internal static bool IsPackedLittleEndian => IsPacked && BitConverter.IsLittleEndian;
#else
        internal static bool IsPacked => false;

        internal static bool IsPackedLittleEndian => false;
#endif
    }
}
