#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// A simple block result object which just carries a byte array.
    /// </summary>
    public sealed class SimpleBlockResult
        : IBlockResult
    {
        private readonly byte[] result;

        /// <summary>
        /// Base constructor - a wrapper for the passed in byte array.
        /// </summary>
        /// <param name="result">The byte array to be wrapped.</param>
        public SimpleBlockResult(byte[] result)
        {
            this.result = result;
        }

        /// <summary>
        /// Return the final result of the operation.
        /// </summary>
        /// <returns>A block of bytes, representing the result of an operation.</returns>
        public byte[] Collect()
        {
            return result;
        }

        /// <summary>
        /// Store the final result of the operation by copying it into the destination array.
        /// </summary>
        /// <returns>The number of bytes copied into destination.</returns>
        /// <param name="buf">The byte array to copy the result into.</param>
        /// <param name="off">The offset into destination to start copying the result at.</param>
        public int Collect(byte[] buf, int off)
        {
            Array.Copy(result, 0, buf, off, result.Length);

            return result.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Collect(Span<byte> output)
        {
            result.CopyTo(output);

            return result.Length;
        }
#endif

        public int GetMaxResultLength() => result.Length;
    }
}
