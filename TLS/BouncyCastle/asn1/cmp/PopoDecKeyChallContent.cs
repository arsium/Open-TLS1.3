#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PopoDecKeyChallContent
	    : Asn1Encodable
	{
        public static PopoDecKeyChallContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoDecKeyChallContent popoDecKeyChallContent)
                return popoDecKeyChallContent;
            return new PopoDecKeyChallContent(Asn1Sequence.GetInstance(obj));
        }

        public static PopoDecKeyChallContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoDecKeyChallContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PopoDecKeyChallContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoDecKeyChallContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

	    private PopoDecKeyChallContent(Asn1Sequence seq)
	    {
	        m_content = seq;
	    }

	    public virtual Challenge[] ToChallengeArray() => m_content.MapElements(Challenge.GetInstance);

	    /**
	     * <pre>
	     * PopoDecKeyChallContent ::= SEQUENCE OF Challenge
	     * </pre>
	     * @return a basic ASN.1 object representation.
	     */
	    public override Asn1Object ToAsn1Object() => m_content;
	}
}
