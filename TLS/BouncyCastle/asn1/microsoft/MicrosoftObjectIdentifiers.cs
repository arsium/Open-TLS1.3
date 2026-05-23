#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Microsoft
{
    // TODO[api] Make static
    public abstract class MicrosoftObjectIdentifiers
    {
        //
        // Microsoft
        //       iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) Microsoft(311)
        //
        public static readonly DerObjectIdentifier Microsoft               = new DerObjectIdentifier("1.3.6.1.4.1.311");
        public static readonly DerObjectIdentifier MicrosoftCertTemplateV1 = Microsoft.Branch("20.2");
        public static readonly DerObjectIdentifier MicrosoftCAVersion      = Microsoft.Branch("21.1");
        public static readonly DerObjectIdentifier MicrosoftPrevCACertHash = Microsoft.Branch("21.2");
        public static readonly DerObjectIdentifier MicrosoftCrlNextPublish = Microsoft.Branch("21.4");
        public static readonly DerObjectIdentifier MicrosoftCertTemplateV2 = Microsoft.Branch("21.7");
        public static readonly DerObjectIdentifier MicrosoftAppPolicies    = Microsoft.Branch("21.10");
    }
}
