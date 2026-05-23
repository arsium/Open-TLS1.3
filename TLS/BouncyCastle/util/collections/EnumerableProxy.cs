#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	internal sealed class EnumerableProxy<T>
		: IEnumerable<T>
	{
		private readonly IEnumerable<T> m_target;

		internal EnumerableProxy(IEnumerable<T> target)
		{
			if (target == null)
				throw new ArgumentNullException(nameof(target));

			m_target = target;
		}

		System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
		{
			return m_target.GetEnumerator();
		}

		public IEnumerator<T> GetEnumerator()
		{
			return m_target.GetEnumerator();
		}
	}
}
