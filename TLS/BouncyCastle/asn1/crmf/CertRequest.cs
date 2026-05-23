#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertRequest
        : Asn1Encodable
    {
        public static CertRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertRequest certRequest)
                return certRequest;
            return new CertRequest(Asn1Sequence.GetInstance(obj));
        }

        public static CertRequest GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRequest(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_certReqId;
        private readonly CertTemplate m_certTemplate;
        private readonly Controls m_controls;

        private CertRequest(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_certReqId = DerInteger.GetInstance(seq[pos++]);
            m_certTemplate = CertTemplate.GetInstance(seq[pos++]);
            m_controls = Asn1Utilities.ReadOptional(seq, ref pos, Controls.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CertRequest(int certReqId, CertTemplate certTemplate, Controls controls)
            : this(DerInteger.ValueOf(certReqId), certTemplate, controls)
        {
        }

        public CertRequest(DerInteger certReqId, CertTemplate certTemplate, Controls controls)
        {
            m_certReqId = certReqId ?? throw new ArgumentNullException(nameof(certReqId));
            m_certTemplate = certTemplate ?? throw new ArgumentNullException(nameof(certTemplate));
            m_controls = controls;
        }

        public virtual DerInteger CertReqID => m_certReqId;

        public virtual CertTemplate CertTemplate => m_certTemplate;

        public virtual Controls Controls => m_controls;

        /**
         * <pre>
         * CertRequest ::= SEQUENCE {
         *                      certReqId     INTEGER,          -- ID for matching request and reply
         *                      certTemplate  CertTemplate,  -- Selected fields of cert to be issued
         *                      controls      Controls OPTIONAL }   -- Attributes affecting issuance
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_certReqId, m_certTemplate);
            v.AddOptional(m_controls);
            return new DerSequence(v);
        }
    }
}
