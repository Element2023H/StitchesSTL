#include <ntifs.h>
#include "GlobalData.hpp"
#include "Lazy.hpp"
#include "NotifyRoutines.hpp"
#include "ProcessCtx.hpp"
#include "Rule.hpp"

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

	LazyInstance<NotifyRoutines, NonPagedPoolNx>::Dispose();

	LazyInstance<ProcessCtx, NonPagedPoolNx>::Dispose();

	LazyInstance<Rules, NonPagedPoolNx>::Dispose();

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
	UNICODE_STRING ustrDllx64;
	RtlInitUnicodeString(&ustrDllx64, L"C:\\InjectDir\\InjectDll_x64.dll");

	UNICODE_STRING ustrDllx86;
	RtlInitUnicodeString(&ustrDllx86, L"C:\\InjectDir\\InjectDll_x86.dll");

	ULONG nAllocDllLength = ustrDllx64.MaximumLength;
	g_pGlobalData->InjectDllx64.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocDllLength, GLOBALDATA_TAG));
	if (g_pGlobalData->InjectDllx64.Buffer)
	{
		RtlZeroMemory(g_pGlobalData->InjectDllx64.Buffer, nAllocDllLength);
		g_pGlobalData->InjectDllx64.Length = 0;
		g_pGlobalData->InjectDllx64.MaximumLength = ustrDllx64.MaximumLength;
		RtlCopyUnicodeString(&g_pGlobalData->InjectDllx64, &ustrDllx64);
	}
	else
	{
		DbgPrint("g_pGlobalData->InjectDllx64.Buffer alloc faid statsus = %08X\r\n", STATUS_NO_MEMORY);
	}

	nAllocDllLength = ustrDllx86.MaximumLength;
	g_pGlobalData->InjectDllx86.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocDllLength, GLOBALDATA_TAG));
	if (g_pGlobalData->InjectDllx86.Buffer)
	{
		RtlZeroMemory(g_pGlobalData->InjectDllx86.Buffer, nAllocDllLength);
		g_pGlobalData->InjectDllx86.Length = 0;
		g_pGlobalData->InjectDllx86.MaximumLength = ustrDllx86.MaximumLength;
		RtlCopyUnicodeString(&g_pGlobalData->InjectDllx86, &ustrDllx86);
	}
	else
	{
		DbgPrint("g_pGlobalData->InjectDllx86.Buffer alloc faid statsus = %08X\r\n", STATUS_NO_MEMORY);
	}

	std::wstring wstrPtProcess{ L"C:\\Windows\\system32\\notepad.exe" };
	rules->AddProtectProcess(wstrPtProcess);
	rules->AddTrustProcess(wstrPtProcess);

	std::wstring wstrPtDir{ L"\\PROTECTFILE\\" };
	rules->AddProtectDir(wstrPtDir);

	std::wstring wstrPtRegistry{ RegistryPath->Buffer };
	rules->AddProtectRegistry(wstrPtRegistry);

	notifyRoutines->Init();

	return status;
}



