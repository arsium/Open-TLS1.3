#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
    internal abstract class ReadOnlyCollection<T>
        : ICollection<T>
    {
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public bool IsReadOnly => true;

        public void Add(T item) => throw new NotSupportedException();
        public void Clear() => throw new NotSupportedException();
        public bool Remove(T item) => throw new NotSupportedException();

        public abstract bool Contains(T item);
        public abstract int Count { get; }
        public abstract void CopyTo(T[] array, int arrayIndex);
        public abstract IEnumerator<T> GetEnumerator();
    }

    internal class ReadOnlyCollectionProxy<T>
        : ReadOnlyCollection<T>
    {
        private readonly ICollection<T> m_target;

        internal ReadOnlyCollectionProxy(ICollection<T> target)
        {
            if (target == null)
                throw new ArgumentNullException(nameof(target));

            m_target = target;
        }

        public override bool Contains(T item) => m_target.Contains(item);
        public override int Count => m_target.Count;
        public override void CopyTo(T[] array, int arrayIndex) => m_target.CopyTo(array, arrayIndex);
        public override IEnumerator<T> GetEnumerator() => m_target.GetEnumerator();
    }
}
