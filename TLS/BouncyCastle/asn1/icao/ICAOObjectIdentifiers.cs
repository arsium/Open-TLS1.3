#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Icao
{
    // TODO[api] Make static
    public abstract class IcaoObjectIdentifiers
	{
		//
		// base id
		//
		public static readonly DerObjectIdentifier IdIcao = new DerObjectIdentifier("2.23.136");

		public static readonly DerObjectIdentifier IdIcaoMrtd = IdIcao.Branch("1");
		public static readonly DerObjectIdentifier IdIcaoMrtdSecurity = IdIcaoMrtd.Branch("1");

		// LDS security object, see ICAO Doc 9303-Volume 2-Section IV-A3.2
		public static readonly DerObjectIdentifier IdIcaoLdsSecurityObject = IdIcaoMrtdSecurity.Branch("1");

		// CSCA master list, see TR CSCA Countersigning and Master List issuance
		public static readonly DerObjectIdentifier IdIcaoCscaMasterList = IdIcaoMrtdSecurity.Branch("2");
		public static readonly DerObjectIdentifier IdIcaoCscaMasterListSigningKey = IdIcaoMrtdSecurity.Branch("3");

		// document type list, see draft TR LDS and PKI Maintenance, par. 3.2.1
		public static readonly DerObjectIdentifier IdIcaoDocumentTypeList = IdIcaoMrtdSecurity.Branch("4");

		// Active Authentication protocol, see draft TR LDS and PKI Maintenance,
		// par. 5.2.2
		public static readonly DerObjectIdentifier IdIcaoAAProtocolObject = IdIcaoMrtdSecurity.Branch("5");

		// CSCA name change and key reoll-over, see draft TR LDS and PKI
		// Maintenance, par. 3.2.1
		public static readonly DerObjectIdentifier IdIcaoExtensions = IdIcaoMrtdSecurity.Branch("6");
		public static readonly DerObjectIdentifier IdIcaoExtensionsNamechangekeyrollover = IdIcaoExtensions.Branch("1");
	}
}
