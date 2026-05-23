#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultMacResult
        : IBlockResult
    {
        private readonly IMac m_mac;

        public DefaultMacResult(IMac mac)
        {
            m_mac = mac;
        }

        public byte[] Collect() => MacUtilities.DoFinal(m_mac);

        public int Collect(byte[] buf, int off) => m_mac.DoFinal(buf, off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Collect(Span<byte> output) => m_mac.DoFinal(output);
#endif

        public int GetMaxResultLength() => m_mac.GetMacSize();
    }
}
