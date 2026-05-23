#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class Dstu4145Parameters
        : ECDomainParameters
    {
        private readonly byte[] m_dke;

        public Dstu4145Parameters(ECDomainParameters ecParameters, byte[] dke)
            : base(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H, ecParameters.GetSeed())
        {
            m_dke = CopyDke(dke);
        }

        public virtual byte[] GetDke() => CopyDke(m_dke);

        private static byte[] CopyDke(byte[] dke) => Arrays.Clone(dke);
    }
}
