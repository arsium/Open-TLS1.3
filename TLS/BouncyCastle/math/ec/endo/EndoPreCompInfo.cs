#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Math.EC.Multiplier;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public class EndoPreCompInfo
        : PreCompInfo
    {
        protected ECEndomorphism m_endomorphism;

        protected ECPoint m_mappedPoint;

        public virtual ECEndomorphism Endomorphism
        {
            get { return m_endomorphism; }
            set { this.m_endomorphism = value; }
        }

        public virtual ECPoint MappedPoint
        {
            get { return m_mappedPoint; }
            set { this.m_mappedPoint = value; }
        }
    }
}
