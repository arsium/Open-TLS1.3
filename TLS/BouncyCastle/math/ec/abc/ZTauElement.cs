#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Math.EC.Abc
{
	/**
	* Class representing an element of <code><b>Z</b>[&#964;]</code>. Let
	* <code>&#955;</code> be an element of <code><b>Z</b>[&#964;]</code>. Then
	* <code>&#955;</code> is given as <code>&#955; = u + v&#964;</code>. The
	* components <code>u</code> and <code>v</code> may be used directly, there
	* are no accessor methods.
	* Immutable class.
	*/
	internal class ZTauElement 
	{
		/**
		* The &quot;real&quot; part of <code>&#955;</code>.
		*/
		public readonly BigInteger u;

		/**
		* The &quot;<code>&#964;</code>-adic&quot; part of <code>&#955;</code>.
		*/
		public readonly BigInteger v;

		/**
		* Constructor for an element <code>&#955;</code> of
		* <code><b>Z</b>[&#964;]</code>.
		* @param u The &quot;real&quot; part of <code>&#955;</code>.
		* @param v The &quot;<code>&#964;</code>-adic&quot; part of
		* <code>&#955;</code>.
		*/
		public ZTauElement(BigInteger u, BigInteger v)
		{
			this.u = u;
			this.v = v;
		}
	}
}
