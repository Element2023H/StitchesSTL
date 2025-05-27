#pragma once
#include <ntifs.h>
#include "Once.hpp"
#include "New.hpp"

namespace Stitches
{
	const ULONG LAZY_INSTANCE_MEM = 'mmyL';

	/// <summary>
	/// A Lazy instance model for static singleton types, it initialize T when it is first accessed
	/// </summary>
	/// <typeparam name="T"></typeparam>
	template <typename T>
	class LazyInstanceBase
	{
	public:
		LazyInstanceBase() = default;
		~LazyInstanceBase() = default;

		LazyInstanceBase(const LazyInstanceBase&) = delete;
		LazyInstanceBase(LazyInstanceBase&&) = delete;
		LazyInstanceBase& operator=(const LazyInstanceBase&) = delete;

	private:
		static Once _Once;
		static T* _Instance;

	public:
		/// <summary>
		/// initialize T using customized function
		/// </summary>
		/// <typeparam name="_Init"></typeparam>
		/// <param name="init"></param>
		/// <returns></returns>
		template <typename _Init>
		FORCEINLINE static void Force(_Init init)
		{
			_Once.CallOnceAndWait([&init]() {
				_Instance = init();
				});
		}

		FORCEINLINE static void Dispose()
		{
			delete _Instance;
			_Once.SetPoisoned();
		}

		FORCEINLINE operator bool() const
		{
			return _Instance != nullptr;
		}

		/// <summary>
		/// initialize T using default CTOR
		/// </summary>
		/// <returns></returns>
		FORCEINLINE T* operator -> ()
		{
			_Once.CallOnceAndWait([this]() {
				_Instance = this->ForceDefault();
				});

			return _Instance;
		}

		FORCEINLINE const T* operator -> () const
		{
			_Once.CallOnceAndWait([this]() {
				_Instance = this->ForceDefault();
				});

			return _Instance;
		}

	private:
		FORCEINLINE T* ForceDefault()
		{
			//return reinterpret_cast<T*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(T), LAZY_INSTANCE_MEM));
			return new T;
		}
	};

	template <typename T>
	T* LazyInstanceBase<T>::_Instance;

	template <typename T>
	Once LazyInstanceBase<T>::_Once;

	template <typename T, ULONG PoolType = PagedPool>
	class LazyInstance;

	template <typename T>
	class LazyInstance<T, PagedPool> : public KMemoryPaged, public LazyInstanceBase<T>
	{

	};

	template <typename T>
	class LazyInstance<T, NonPagedPoolNx> : public KMemoryNonPaged, public LazyInstanceBase<T>
	{

	};
}