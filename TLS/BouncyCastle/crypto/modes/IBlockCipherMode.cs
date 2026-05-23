#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto.Modes
{
    public interface IBlockCipherMode
        : IBlockCipher
    {
        /// <summary>Return the <code cref="IBlockCipher"/> underlying this cipher mode.</summary>
        IBlockCipher UnderlyingCipher { get; }

        /// <summary>Indicates whether this cipher mode can handle partial blocks.</summary>
        bool IsPartialBlockOkay { get; }

        /// <summary>
        /// Reset the cipher mode to the same state as it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
