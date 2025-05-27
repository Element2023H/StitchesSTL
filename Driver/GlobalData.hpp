#pragma once
#include "Api.hpp"
#include "Imports.hpp"

constexpr ULONG GLOBALDATA_TAG = 'tdGS';

struct GlobalData
{
	GlobalData()
	{
		fnZwQueryInformationProcess.Init(L"ZwQueryInformationProcess");
		fnZwQuerySystemInformation.Init(L"ZwQuerySystemInformation");
		fnCmCallbackGetKeyObjectIDEx.Init(L"CmCallbackGetKeyObjectIDEx");
		fnCmCallbackReleaseKeyObjectIDEx.Init(L"CmCallbackReleaseKeyObjectIDEx");

		PsIsProtectedProcess.Init(L"PsIsProtectedProcess");
		PsIsProtectedProcessLight.Init(L"PsIsProtectedProcessLight");
		ZwTerminateProcess.Init(L"ZwTerminateProcess");
		PsGetProcessWow64Process.Init(L"PsGetProcessWow64Process");

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
		pfnPsSetCreateProcessNotifyRoutineEx2.Init(L"PsSetCreateProcessNotifyRoutineEx2");
#else
		pfnPsSetCreateProcessNotifyRoutineEx.Init(L"PsSetCreateProcessNotifyRoutineEx");
#endif
	}

	~GlobalData()
	{
		if (InjectDllx64.Buffer)
		{
			ExFreePool(InjectDllx64.Buffer);
			InjectDllx64.Buffer = nullptr;
		}
		if (InjectDllx86.Buffer)
		{
			ExFreePool(InjectDllx86.Buffer);
			InjectDllx86.Buffer = nullptr;
		}
	}

	PDRIVER_OBJECT							pDriverObject = nullptr;
	PDEVICE_OBJECT							pDeviceObject = nullptr;
	PFLT_FILTER								pFileFilter = nullptr;

	NtFunction<PZwQueryInformationProcess>		fnZwQueryInformationProcess;
	NtFunction<PZwQuerySystemInformation>		fnZwQuerySystemInformation;
	NtFunction<PCmCallbackGetKeyObjectIDEx>		fnCmCallbackGetKeyObjectIDEx;
	NtFunction<PCmCallbackReleaseKeyObjectIDEx> fnCmCallbackReleaseKeyObjectIDEx;

	//
	// process Notify
	//
	NtFunction<PfnPsSetCreateProcessNotifyRoutineEx> pfnPsSetCreateProcessNotifyRoutineEx;
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	NtFunction<PfnPsSetCreateProcessNotifyRoutineEx> pfnPsSetCreateProcessNotifyRoutineEx2;
#endif

	// APC Injector
	UNICODE_STRING InjectDllx64{};
	UNICODE_STRING InjectDllx86{};

	//
	// Signing verification API
	//
	NtFunction<PPsIsProtectedProcess>			PsIsProtectedProcess;
	NtFunction<PPsIsProtectedProcessLight>		PsIsProtectedProcessLight;
	NtFunction<PPsGetProcessSignatureLevel>		PsGetProcessSignatureLevel;
	NtFunction<PSeGetCachedSigningLevel>		SeGetCachedSigningLevel;
	NtFunction<PNtSetCachedSigningLevel>		NtSetCachedSigningLevel;
	NtFunction<PPsGetProcessWow64Process>		PsGetProcessWow64Process;
	NtFunction<PPsWrapApcWow64Thread>			PsWrapApcWow64Thread;


	NtFunction<PfnZwTerminateProcess>			ZwTerminateProcess;


	volatile VolumeControlFlag					volumeControlFlag;
};