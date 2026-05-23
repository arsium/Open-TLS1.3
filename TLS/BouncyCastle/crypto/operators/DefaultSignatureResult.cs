#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultSignatureResult
        : IBlockResult
    {
        private readonly ISigner m_signer;

        public DefaultSignatureResult(ISigner signer)
        {
            m_signer = signer;
        }

        public byte[] Collect() => m_signer.GenerateSignature();

        public int Collect(byte[] buf, int off)
        {
            byte[] signature = Collect();
            signature.CopyTo(buf, off);
            return signature.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Collect(Span<byte> output)
        {
            byte[] signature = Collect();
            signature.CopyTo(output);
            return signature.Length;
        }
#endif

        public int GetMaxResultLength() => m_signer.GetMaxSignatureSize();
    }
}
