#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
#endif

namespace Org.BouncyCastle.Utilities
{
    public static class Shorts
    {
        public const int NumBits = 16;
        public const int NumBytes = 2;

        public static short ReverseBytes(short i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i, 8);
#endif
        }

        [CLSCompliant(false)]
        public static ushort ReverseBytes(ushort i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i, 8);
#endif
        }

        public static short RotateLeft(short i, int distance)
        {
            return (short)RotateLeft((ushort)i, distance);
        }

        [CLSCompliant(false)]
        public static ushort RotateLeft(ushort i, int distance)
        {
            return (ushort)((i << distance) | (i >> (16 - distance)));
        }

        public static short RotateRight(short i, int distance)
        {
            return (short)RotateRight((ushort)i, distance);
        }

        [CLSCompliant(false)]
        public static ushort RotateRight(ushort i, int distance)
        {
            return (ushort)((i >> distance) | (i << (16 - distance)));
        }
    }
}
