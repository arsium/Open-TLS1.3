#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.IO;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for cryptographic operations such as Hashes, MACs, and Signatures which reduce a stream of data
    /// to a single value.
    /// </summary>
    public interface IStreamCalculator<out TResult>
    {
        /// <summary>Return a "sink" stream which only exists to update the implementing object.</summary>
        /// <returns>A stream to write to in order to update the implementing object.</returns>
        Stream Stream { get; }

        /// <summary>
        /// Return the result of processing the stream. This value is only available once the stream
        /// has been closed.
        /// </summary>
        /// <returns>The result of processing the stream.</returns>
        TResult GetResult();
    }
}
