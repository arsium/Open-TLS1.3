#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1
{
    internal class ConstructedILEncoding
        : IAsn1Encoding
    {
        private readonly int m_tagClass;
        private readonly int m_tagNo;
        private readonly IAsn1Encoding[] m_contentsElements;

        internal ConstructedILEncoding(int tagClass, int tagNo, IAsn1Encoding[] contentsElements)
        {
            m_tagClass = tagClass;
            m_tagNo = tagNo;
            m_contentsElements = contentsElements;
        }

        void IAsn1Encoding.Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteIdentifier(Asn1Tags.Constructed | m_tagClass, m_tagNo);
            asn1Out.WriteByte(0x80);
            asn1Out.EncodeContents(m_contentsElements);
            asn1Out.WriteByte(0x00);
            asn1Out.WriteByte(0x00);
        }

        int IAsn1Encoding.GetLength()
        {
            return Asn1OutputStream.GetLengthOfEncodingIL(m_tagNo, m_contentsElements);
        }
    }
}
