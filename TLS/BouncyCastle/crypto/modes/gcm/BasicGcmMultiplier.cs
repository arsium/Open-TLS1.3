#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    [Obsolete("Will be removed")]
    public class BasicGcmMultiplier
        : IGcmMultiplier
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsHardwareAccelerated => Org.BouncyCastle.Runtime.Intrinsics.X86.Pclmulqdq.IsEnabled;
#else
        internal static bool IsHardwareAccelerated => false;
#endif

        private GcmUtilities.FieldElement H;

        public void Init(byte[] H)
        {
            GcmUtilities.AsFieldElement(H, out this.H);
        }

        public void MultiplyH(byte[] x)
        {
            GcmUtilities.AsFieldElement(x, out var T);
            GcmUtilities.Multiply(ref T, ref H);
            GcmUtilities.AsBytes(ref T, x);
        }
    }
}
