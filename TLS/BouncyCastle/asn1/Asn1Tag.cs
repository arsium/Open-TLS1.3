#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1
{
    internal sealed class Asn1Tag
    {
        internal static Asn1Tag Create(int tagClass, int tagNo)
        {
            return new Asn1Tag(tagClass, tagNo);
        }

        private readonly int m_tagClass;
        private readonly int m_tagNo;

        private Asn1Tag(int tagClass, int tagNo)
        {
            m_tagClass = tagClass;
            m_tagNo = tagNo;
        }

        internal int TagClass
        {
            get { return m_tagClass; }
        }

        internal int TagNo
        {
            get { return m_tagNo; }
        }
    }
}
