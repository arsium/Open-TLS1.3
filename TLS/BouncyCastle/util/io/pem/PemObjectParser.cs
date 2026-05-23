#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
	public interface PemObjectParser
	{
		/// <param name="obj">
		/// A <see cref="PemObject"/>
		/// </param>
		/// <returns>
		/// An <see cref="object"/>
		/// </returns>
		/// <exception cref="IOException"></exception>
		object ParseObject(PemObject obj);
	}
}
