#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /**
     * Class holding precomputation data for fixed-point multiplications.
     */
    public class FixedPointPreCompInfo
        : PreCompInfo
    {
        protected ECPoint m_offset = null;

        /**
         * Lookup table for the precomputed <code>ECPoint</code>s used for a fixed point multiplication.
         */
        protected ECLookupTable m_lookupTable = null;

        /**
         * The width used for the precomputation. If a larger width precomputation
         * is already available this may be larger than was requested, so calling
         * code should refer to the actual width.
         */
        protected int m_width = -1;

        public virtual ECLookupTable LookupTable
        {
            get { return m_lookupTable; }
            set { this.m_lookupTable = value; }
        }

        public virtual ECPoint Offset
        {
			get { return m_offset; }
			set { this.m_offset = value; }
		}

        public virtual int Width
        {
            get { return m_width; }
            set { this.m_width = value; }
        }
    }
}
