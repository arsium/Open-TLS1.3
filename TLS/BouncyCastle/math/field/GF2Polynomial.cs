#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.Field
{
    internal class GF2Polynomial
        : IPolynomial
    {
        protected readonly int[] exponents;

        internal GF2Polynomial(int[] exponents)
        {
            this.exponents = Arrays.Clone(exponents);
        }

        public virtual int Degree
        {
            get { return exponents[exponents.Length - 1]; }
        }

        public virtual int[] GetExponentsPresent()
        {
            return Arrays.Clone(exponents);
        }

        public override bool Equals(object obj)
        {
            if (this == obj)
            {
                return true;
            }
            GF2Polynomial other = obj as GF2Polynomial;
            if (null == other)
            {
                return false;
            }
            return Arrays.AreEqual(exponents, other.exponents);
        }

        public override int GetHashCode()
        {
            return Arrays.GetHashCode(exponents);
        }
    }
}
