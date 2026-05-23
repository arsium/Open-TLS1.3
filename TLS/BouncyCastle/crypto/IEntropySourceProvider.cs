#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface describing a provider of entropy sources.
    /// </summary>
    public interface IEntropySourceProvider
    {
        /// <summary>
        /// Return an entropy source providing a block of entropy.
        /// </summary>
        /// <param name="bitsRequired">The size of the block of entropy required.</param>
        /// <returns>An entropy source providing bitsRequired blocks of entropy.</returns>
        IEntropySource Get(int bitsRequired);
    }
}
