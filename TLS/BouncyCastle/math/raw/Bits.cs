#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

namespace Org.BouncyCastle.Math.Raw
{
    internal static class Bits
    {
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal static uint BitPermuteStep(uint x, uint m, int s)
        {
            Debug.Assert((m & (m << s)) == 0U);
            Debug.Assert((m << s) >> s == m);

            uint t = (x ^ (x >> s)) & m;
            return t ^ (t << s) ^ x;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal static ulong BitPermuteStep(ulong x, ulong m, int s)
        {
            Debug.Assert((m & (m << s)) == 0UL);
            Debug.Assert((m << s) >> s == m);

            ulong t = (x ^ (x >> s)) & m;
            return t ^ (t << s) ^ x;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal static void BitPermuteStep2(ref uint hi, ref uint lo, uint m, int s)
        {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP1_1_OR_GREATER
            Debug.Assert(!Unsafe.AreSame(ref hi, ref lo) || (m & (m << s)) == 0U);
#endif
            Debug.Assert((m << s) >> s == m);

            uint t = ((lo >> s) ^ hi) & m;
            lo ^= t << s;
            hi ^= t;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal static void BitPermuteStep2(ref ulong hi, ref ulong lo, ulong m, int s)
        {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP1_1_OR_GREATER
            Debug.Assert(!Unsafe.AreSame(ref hi, ref lo) || (m & (m << s)) == 0UL);
#endif
            Debug.Assert((m << s) >> s == m);

            ulong t = ((lo >> s) ^ hi) & m;
            lo ^= t << s;
            hi ^= t;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal static uint BitPermuteStepSimple(uint x, uint m, int s)
        {
            Debug.Assert((m << s) == ~m);
            Debug.Assert((m & ~m) == 0U);

            return ((x & m) << s) | ((x >> s) & m);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal static ulong BitPermuteStepSimple(ulong x, ulong m, int s)
        {
            Debug.Assert((m << s) == ~m);
            Debug.Assert((m & ~m) == 0UL);

            return ((x & m) << s) | ((x >> s) & m);
        }
    }
}
