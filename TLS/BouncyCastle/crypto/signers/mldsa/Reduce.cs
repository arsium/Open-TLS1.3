#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal static class Reduce
    {
        public static int MontgomeryReduce(long a)
        {
            int t = (int)(a * MLDsaEngine.QInv);
            return (int)((a - (long)t * MLDsaEngine.Q) >> 32);
        }

        public static int Reduce32(int a)
        {
            int t = (a + (1 << 22)) >> 23;
            return a - t * MLDsaEngine.Q;
        }

        public static int ConditionalAddQ(int a) => a + ((a >> 31) & MLDsaEngine.Q);
    }
}
