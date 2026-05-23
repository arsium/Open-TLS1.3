#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Base interface for general purpose byte derivation functions.</summary>
    public interface IDerivationFunction
    {
        void Init(IDerivationParameters parameters);

        /// <summary>The message digest used as the basis for the function.</summary>
        IDigest Digest { get; }

        int GenerateBytes(byte[] output, int outOff, int length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        int GenerateBytes(Span<byte> output);
#endif
    }
}
