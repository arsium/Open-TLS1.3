#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Utilities.Collections
{
    /// <summary>Interface for matching objects in an <see cref="IStore{T}"/>.</summary>
    /// <typeparam name="T">The contravariant type of selectable objects.</typeparam>
    public interface ISelector<in T>
        : ICloneable
    {
        /// <summary>Match the passed in object, returning true if it would be selected by this selector, false
        /// otherwise.</summary>
        /// <param name="candidate">The object to be matched.</param>
        /// <returns><code>true</code> if the objects is matched by this selector, false otherwise.</returns>
        bool Match(T candidate);
    }
}
