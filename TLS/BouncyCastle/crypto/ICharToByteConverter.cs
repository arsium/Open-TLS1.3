#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for a converter that produces a byte encoding for a char array.
    /// </summary>
    public interface ICharToByteConverter
    {
        /// <summary>The name of the conversion.</summary>
        string Name { get; }

        /// <summary>Return a byte encoded representation of the passed in password.</summary>
        /// <param name="password">the characters to encode.</param>
        /// <return>a byte encoding of password.</return>
        byte[] Convert(char[] password);
    }
}
