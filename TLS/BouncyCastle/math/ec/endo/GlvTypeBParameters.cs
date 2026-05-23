#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public class GlvTypeBParameters
    {
        protected readonly BigInteger m_beta, m_lambda;
        protected readonly ScalarSplitParameters m_splitParams;

        public GlvTypeBParameters(BigInteger beta, BigInteger lambda, ScalarSplitParameters splitParams)
        {
            this.m_beta = beta;
            this.m_lambda = lambda;
            this.m_splitParams = splitParams;
        }

        public virtual BigInteger Beta
        {
            get { return m_beta; }
        }

        public virtual BigInteger Lambda
        {
            get { return m_lambda; }
        }

        public virtual ScalarSplitParameters SplitParams
        {
            get { return m_splitParams; }
        }
    }
}
