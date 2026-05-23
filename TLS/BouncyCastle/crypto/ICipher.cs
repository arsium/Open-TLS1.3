#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a ciphers that do not require data to be block aligned.
    /// <para>
    /// Note: In cases where the underlying algorithm is block based, these ciphers may add or remove padding as needed.
    /// </para>
    /// </summary>
    public interface ICipher
    {
        /// <summary>
        /// Return the size of the output buffer required for a Write() plus a
        /// close() with the write() being passed inputLen bytes.
        /// <para>
        /// The returned size may be dependent on the initialisation of this cipher
        /// and may not be accurate once subsequent input data is processed as the cipher may
        /// add, add or remove padding, as it sees fit.
        /// </para>
        /// </summary>
        /// <returns>The space required to accommodate a call to processBytes and doFinal with inputLen bytes of input.</returns>
        /// <param name="inputLen">The length of the expected input.</param>
        int GetMaxOutputSize(int inputLen);

        /// <summary>
        /// Return the size of the output buffer required for a write() with the write() being
        /// passed inputLen bytes and just updating the cipher output.
        /// </summary>
        /// <returns>The space required to accommodate a call to processBytes with inputLen bytes of input.</returns>
        /// <param name="inputLen">The length of the expected input.</param>
        int GetUpdateOutputSize(int inputLen);

        /// <summary>
        /// Gets the stream for reading/writing data processed/to be processed.
        /// </summary>
        /// <value>The stream associated with this cipher.</value>
        Stream Stream { get; }
    }
}
