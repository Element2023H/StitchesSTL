#include <ntifs.h>
#include "GlobalData.hpp"
#include "Lazy.hpp"

using namespace Stitches;

LazyInstance<GlobalData, NonPagedPoolNx> g_pGlobalData;

EXTERN_C
{
NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath);

VOID
DriverUnload(PDRIVER_OBJECT DriverObject);

};

#if defined(ALLOC_PRAGMA)

#pragma alloc_text(INIT, DriverMain)
#pragma alloc_text(PAGE, DriverUnload)

#endif

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	LazyInstance<GlobalData, NonPagedPoolNx>::Dispose();
}

NTSTATUS 
DriverMain(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status{ STATUS_SUCCESS };

	DbgBreakPoint();
	DriverObject->DriverUnload = DriverUnload;

	// initialize g_pGlobalData
	LazyInstance<GlobalData>::Force([DriverObject]() {
		auto data = new GlobalData{};

		if (!data)
		{
			return (GlobalData*)nullptr;
		}

		// set driver object
		data->pDriverObject = DriverObject;
		return data;
		});

	if (!g_pGlobalData)
	{
		DbgPrint("g_pGlobalData alloc failed\r\n");
		return STATUS_NO_MEMORY;
	}

	

	return status;
}



