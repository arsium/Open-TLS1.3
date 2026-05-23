#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultDigestCalculator
        : IStreamCalculator<IBlockResult>
    {
        private readonly DigestSink m_digestSink;

        public DefaultDigestCalculator(IDigest digest)
        {
            m_digestSink = new DigestSink(digest);
        }

        public Stream Stream => m_digestSink;

        public IBlockResult GetResult() => new DefaultDigestResult(m_digestSink.Digest);
    }
}
