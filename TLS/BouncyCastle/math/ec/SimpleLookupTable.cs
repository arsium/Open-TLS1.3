#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Math.EC
{
    public class SimpleLookupTable
        : AbstractECLookupTable
    {
        private static ECPoint[] Copy(ECPoint[] points, int off, int len)
        {
            ECPoint[] result = new ECPoint[len];
            for (int i = 0; i < len; ++i)
            {
                result[i] = points[off + i];
            }
            return result;
        }

        private readonly ECPoint[] points;

        public SimpleLookupTable(ECPoint[] points, int off, int len)
        {
            this.points = Copy(points, off, len);
        }

        public override int Size
        {
            get { return points.Length; }
        }

        public override ECPoint Lookup(int index)
        {
            throw new NotSupportedException("Constant-time lookup not supported");
        }

        public override ECPoint LookupVar(int index)
        {
            return points[index];
        }
    }
}
