#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
    internal sealed class StoreImpl<T>
        : IStore<T>
    {
        private readonly List<T> m_contents;

        internal StoreImpl(IEnumerable<T> e)
        {
            m_contents = new List<T>(e);
        }

        IEnumerable<T> IStore<T>.EnumerateMatches(ISelector<T> selector)
        {
            foreach (T candidate in m_contents)
            {
                if (selector == null || selector.Match(candidate))
                    yield return candidate;
            }
        }
    }
}
