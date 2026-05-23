#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
    /// <summary>A generic interface describing a simple store of objects.</summary>
    /// <typeparam name="T">The covariant type of stored objects.</typeparam>
    public interface IStore<out T>
    {
        /// <summary>Enumerate the (possibly empty) collection of objects matched by the given selector.</summary>
        /// <param name="selector">The <see cref="ISelector{T}"/> used to select matching objects.</param>
        /// <returns>An <see cref="IEnumerable{T}"/> of the matching objects.</returns>
        IEnumerable<T> EnumerateMatches(ISelector<T> selector);
    }
}
