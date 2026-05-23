#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.Diagnostics;

namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal class PolyVecMatrix
    {
        private readonly PolyVec[] m_matrix;

        public PolyVecMatrix(MLDsaEngine engine)
        {
            int K = engine.K;
            int L = engine.L;

            m_matrix = new PolyVec[K];
            for (int i = 0; i < K; i++)
            {
                m_matrix[i] = new PolyVec(engine, L);
            }
        }

        public void ExpandMatrix(byte[] rho)
        {
            for (int i = 0; i < m_matrix.Length; ++i)
            {
                m_matrix[i].UniformBlocks(rho, i << 8);
            }
        }

        public void PointwiseMontgomery(PolyVec t, PolyVec v)
        {
            Debug.Assert(t.Length == m_matrix.Length);

            for (int i = 0; i < m_matrix.Length; ++i)
            {
                t[i].PointwiseAccountMontgomery(m_matrix[i], v);
            }
        }
    }
}
