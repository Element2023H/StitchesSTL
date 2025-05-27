#include "NotifyRoutines.hpp"
#include "GlobalData.hpp"
#include "KUtils.hpp"
#include "APCInject.hpp"
#include "ProcessCtx.hpp"

using namespace Stitches;

extern LazyInstance<GlobalData, NonPagedPoolNx> g_pGlobalData;

ThreadNotify::~ThreadNotify()
{
	if (FALSE == m_bInitialized)
	{
		return;
	}

	PsRemoveCreateThreadNotifyRoutine(reinterpret_cast<PCREATE_THREAD_NOTIFY_ROUTINE>(ThreadNotifyRoutine));
}

NTSTATUS ThreadNotify::Init()
{
	if (TRUE == m_bInitialized)
	{
		return STATUS_SUCCESS;
	}

	NTSTATUS status = PsSetCreateThreadNotifyRoutine(reinterpret_cast<PCREATE_THREAD_NOTIFY_ROUTINE>(ThreadNotifyRoutine));
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Thread Notify Created failed status = %08x\r\n", status);
	}
	else
	{
		m_bInitialized = TRUE;
		return status;
	}

	return STATUS_SUCCESS;
}

VOID
ThreadNotify::ThreadNotifyRoutine(
	IN HANDLE ProcessId, 
	IN HANDLE ThreadId, 
	IN BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);


	if (Create)
	{
		if (ULongToHandle(4) >= PsGetCurrentProcessId())
		{
			return;
		}


		// 这里需要注意  还是需要配合进程上下文使用
		// 因为这样的判断会导致 父进程创建子进程的情况
		// 最好是判断父进程pid是否和processid相等的情况
		auto bRemoteThread = [&]() { return (PsGetCurrentProcessId() != ProcessId) &&
			(PsInitialSystemProcess != PsGetCurrentProcessId()) &&
			(ProcessId != PsGetProcessId(PsInitialSystemProcess));
		};

		if (bRemoteThread())
		{
			WCHAR wszProcessPath[MAX_PATH] = { 0 };

			GetProcessImageByPid(ProcessId, wszProcessPath);

			WCHAR wszFxxk[MAX_PATH] = { 0 };
			GetProcessImageByPid(PsGetCurrentProcessId(), wszFxxk);
		}
	}
}

ProcessNotify::~ProcessNotify()
{
	if (FALSE == m_bInitialized)
	{
		return;
	}

	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx)
	{
		g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(ProcessNotifyRoutine), TRUE);
	}
}

NTSTATUS ProcessNotify::Init()
{
	NTSTATUS status{ STATUS_SUCCESS };

	if (TRUE == m_bInitialized)
	{
		return STATUS_SUCCESS;
	}
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx)
	{

		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(ProcessNotifyRoutine), FALSE);
		if (NT_SUCCESS(status))
		{
			m_bInitialized = TRUE;
			return status;
		}
		else
		{
			m_bInitialized = FALSE;
			return status;
		}
	}
	else
	{
		m_bInitialized = FALSE;
		return STATUS_UNSUCCESSFUL;
	}
}

VOID 
ProcessNotify::ProcessNotifyRoutine(
	IN OUT PEPROCESS Process, 
	IN OUT HANDLE ProcessId,
	IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);

	if (CreateInfo)
	{
		if (CreateInfo->FileOpenNameAvailable)
		{
			processCtx->AddProcessContext(Process, ProcessId, CreateInfo);

			// test ... .. .
			if (UnicodeStringContains(const_cast<PUNICODE_STRING>(CreateInfo->ImageFileName), L"mimikatz.exe"))
			{
				// block process create
				CreateInfo->CreationStatus = STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY;
				return;
			}
		}
	}
	else
	{
		processCtx->DeleteProcessCtxByPid(ProcessId);
	}
}

ImageNotify::~ImageNotify()
{
	if (FALSE == m_bInitialized)
	{
		return;
	}

	PsRemoveLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(ImageNotifyRoutine));
}

NTSTATUS ImageNotify::Init()
{
	if (TRUE == m_bInitialized)
	{
		return STATUS_SUCCESS;
	}
	NTSTATUS status{ STATUS_SUCCESS };
	status = PsSetLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(ImageNotifyRoutine));
	if (NT_SUCCESS(status))
	{
		m_bInitialized = TRUE;
	}
	else
	{
		m_bInitialized = FALSE;
	}
	return status;
}

VOID 
ImageNotify::ImageNotifyRoutine(
	_In_ PUNICODE_STRING FullImageName, 
	_In_ HANDLE ProcessId, 
	_In_ PIMAGE_INFO ImageInfo)
{
	NTSTATUS status{ STATUS_SUCCESS };
	
	ProcessInfo* pProcessInfo = processCtx->FindProcessCtxByPid(ProcessId);
	if (pProcessInfo && pProcessInfo->ProcessPath.size())
	{
		DbgBreakPoint();
		if (KWstrnstr(pProcessInfo->ProcessPath.c_str(), L"system32\\notepad.exe") &&
			KWstrnstr(FullImageName->Buffer, L"system32\\ntdll.dll"))
		{
			DbgBreakPoint();
			ApcInjectNativeProcess(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx64);
		}
		else if (KWstrnstr(pProcessInfo->ProcessPath.c_str(), L"SysWOW64\\notepad.exe") &&
			KWstrnstr(FullImageName->Buffer, L"SysWOW64\\ntdll.dll"))
		{
			ApcInjectWow64Process(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx86);
		}
	}
	else
	{
		PUNICODE_STRING pProcessImage{ nullptr };
		PEPROCESS pProcess{ nullptr };
		status = PsLookupProcessByProcessId(ProcessId, &pProcess);
		if (!NT_SUCCESS(status))
		{
			return;
		}

		status = SeLocateProcessImageName(pProcess, &pProcessImage);
		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(pProcess);
			return;
		}

		// test ... .. .
		if (pProcessImage && pProcessImage->Buffer)
		{
			if (KWstrnstr(pProcessImage->Buffer, L"system32\\notepad.exe") &&
				KWstrnstr(FullImageName->Buffer, L"system32\\ntdll.dll"))
			{
				DbgBreakPoint();
				ApcInjectNativeProcess(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx64);
			}
			else if (KWstrnstr(pProcessImage->Buffer, L"SysWOW64\\notepad.exe") &&
				KWstrnstr(FullImageName->Buffer, L"SysWOW64\\ntdll.dll"))
			{
				ApcInjectWow64Process(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx86);
			}

			ExFreePool(pProcessImage);
			ObDereferenceObject(pProcess);
		}
	}
}

NTSTATUS NotifyRoutines::Init()
{
	NTSTATUS status{ STATUS_SUCCESS };

	status = m_ProcessNotify.Init();
	status = m_ThreadNotify.Init();
	status = m_ImageNotify.Init();

	return status;
}
