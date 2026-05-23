#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Operators that reduce their input to the validation of a signature produce this type.
    /// </summary>
    public interface IVerifier
    {
        /// <summary>
        /// Return true if the passed in data matches what is expected by the verification result.
        /// </summary>
        /// <param name="data">The bytes representing the signature.</param>
        /// <returns>true if the signature verifies, false otherwise.</returns>
        bool IsVerified(byte[] data);

        /// <summary>
        /// Return true if the length bytes from off in the source array match the signature
        /// expected by the verification result.
        /// </summary>
        /// <param name="source">Byte array containing the signature.</param>
        /// <param name="off">The offset into the source array where the signature starts.</param>
        /// <param name="length">The number of bytes in source making up the signature.</param>
        /// <returns>true if the signature verifies, false otherwise.</returns>
        bool IsVerified(byte[] source, int off, int length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api]
        //bool IsVerified(ReadOnlySpan<byte> data);
#endif
    }
}
