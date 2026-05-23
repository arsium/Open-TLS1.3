#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1
{
    internal class PrimitiveEncodingSuffixed
        : IAsn1Encoding
    {
        private readonly int m_tagClass;
        private readonly int m_tagNo;
        private readonly byte[] m_contentsOctets;
        private readonly byte m_contentsSuffix;

        internal PrimitiveEncodingSuffixed(int tagClass, int tagNo, byte[] contentsOctets, byte contentsSuffix)
        {
            m_tagClass = tagClass;
            m_tagNo = tagNo;
            m_contentsOctets = contentsOctets;
            m_contentsSuffix = contentsSuffix;
        }

        void IAsn1Encoding.Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteIdentifier(m_tagClass, m_tagNo);
            asn1Out.WriteDL(m_contentsOctets.Length);
            asn1Out.Write(m_contentsOctets, 0, m_contentsOctets.Length - 1);
            asn1Out.WriteByte(m_contentsSuffix);
        }

        int IAsn1Encoding.GetLength()
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(m_tagNo, m_contentsOctets.Length);
        }
    }
}
