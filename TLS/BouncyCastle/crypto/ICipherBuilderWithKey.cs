#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// A cipher builder that can also return the key it was initialized with.
    /// </summary>
    public interface ICipherBuilderWithKey
        : ICipherBuilder
    {
        /// <summary>
        /// Return the key we were initialized with.
        /// </summary>
        ICipherParameters Key { get; }
    }
}
