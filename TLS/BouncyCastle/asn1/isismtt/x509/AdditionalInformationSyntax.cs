#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
	* Some other information of non-restrictive nature regarding the usage of this
	* certificate.
	* 
	* <pre>
	*    AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
	* </pre>
	*/
    public class AdditionalInformationSyntax
		: Asn1Encodable
	{
        public static AdditionalInformationSyntax GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AdditionalInformationSyntax additionalInformationSyntax)
                return additionalInformationSyntax;
            return new AdditionalInformationSyntax(DirectoryString.GetInstance(obj));
        }

        public static AdditionalInformationSyntax GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AdditionalInformationSyntax(DirectoryString.GetInstance(taggedObject, declaredExplicit));

        public static AdditionalInformationSyntax GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AdditionalInformationSyntax(DirectoryString.GetTagged(taggedObject, declaredExplicit));

        private readonly DirectoryString m_information;

        private AdditionalInformationSyntax(DirectoryString information)
		{
            // TODO Length constraint?
            m_information = information;
		}

		/**
		* Constructor from a given details.
		*
		* @param information The description of the information.
		*/
		public AdditionalInformationSyntax(string information)
		{
            // TODO Length constraint?
            m_information = new DirectoryString(information);
		}

		public virtual DirectoryString Information => m_information;

		/**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*   AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
		* </pre>
		*
		* @return an Asn1Object
		*/
		public override Asn1Object ToAsn1Object() => m_information.ToAsn1Object();
	}
}
