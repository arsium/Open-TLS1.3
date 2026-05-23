#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.Threading;

namespace Org.BouncyCastle.Utilities
{
    public static class Objects
    {
        public static int GetHashCode(object obj)
        {
            return null == obj ? 0 : obj.GetHashCode();
        }

        internal static TValue EnsureSingletonInitialized<TValue, TArg>(ref TValue value, TArg arg,
            Func<TArg, TValue> initialize)
            where TValue : class
        {
            TValue currentValue = Volatile.Read(ref value);
            if (null != currentValue)
                return currentValue;

            TValue candidateValue = initialize(arg);

            return Interlocked.CompareExchange(ref value, candidateValue, null) ?? candidateValue;
        }
    }
}
