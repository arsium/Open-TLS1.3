#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Runtime.CompilerServices;

#nullable enable

namespace Org.BouncyCastle.Utilities
{
    internal static class Spans
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void CopyFrom<T>(this Span<T> output, ReadOnlySpan<T> input)
        {
            input[..output.Length].CopyTo(output);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Span<T> FromNullable<T>(T[]? array)
        {
            return array == null ? Span<T>.Empty : array.AsSpan();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Span<T> FromNullable<T>(T[]? array, int start)
        {
            return array == null ? Span<T>.Empty : array.AsSpan(start);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ReadOnlySpan<T> FromNullableReadOnly<T>(T[]? array)
        {
            return array == null ? Span<T>.Empty : array.AsSpan();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ReadOnlySpan<T> FromNullableReadOnly<T>(T[]? array, int start)
        {
            return array == null ? Span<T>.Empty : array.AsSpan(start);
        }
    }
}
#endif
