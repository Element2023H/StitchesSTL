#pragma once
#include "Imports.hpp"

namespace Stitches
{
	template <POOL_TYPE PoolType = PagedPool>
	class KMemory
	{
	public:
#pragma warning(push)
#pragma warning(disable: 4100)

		void* operator new(size_t sz) noexcept
		{
			void* ptr = ExAllocatePoolWithTag(PoolType, sz, KOBJ_TAG);

			return ptr;
		}

		void operator delete(void* ptr, size_t sz) noexcept
		{
			if (ptr)
				ExFreePoolWithTag(ptr, KOBJ_TAG);
		}

#pragma warning(pop)
	};

	class KMemoryPaged :
		public KMemory<PagedPool>
	{

	};

	class KMemoryNonPaged :
		public KMemory<NonPagedPoolNx>
	{

	};
};

