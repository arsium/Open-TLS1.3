#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿namespace Org.BouncyCastle.Runtime.Intrinsics.X86
{
    internal static class Pclmulqdq
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported;
#else
        internal static bool IsEnabled => false;
#endif

        internal static class V256
        {
#if NET10_0_OR_GREATER
            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.V256.IsSupported;
#else
            internal static bool IsEnabled => false;
#endif
        }

        internal static class V512
        {
#if NET10_0_OR_GREATER
            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.V512.IsSupported;
#else
            internal static bool IsEnabled => false;
#endif
        }

//        internal static class X64
//        {
//#if NETCOREAPP3_0_OR_GREATER
//            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.X64.IsSupported;
//#else
//            internal static bool IsEnabled => false;
//#endif
//        }
    }
}
