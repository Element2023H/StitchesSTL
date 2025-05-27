#include "NotifyRoutines.hpp"
#include "GlobalData.hpp"
#include "KUtils.hpp"
#include "APCInject.hpp"
#include "ProcessCtx.hpp"
#include <algorithm>
#include <cwctype>

using namespace Stitches;

extern LazyInstance<GlobalData, NonPagedPoolNx> g_pGlobalData;

constexpr ULONG MAX_REGISTRYPATH = MAX_PATH * 2;

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000) 


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
		if (KWstrnstr(pProcessInfo->ProcessPath.c_str(), L"system32\\notepad.exe") &&
			KWstrnstr(FullImageName->Buffer, L"system32\\ntdll.dll"))
		{
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
	status = m_RegistryNotify.Init();
	status = m_ObjectNotify.Init();

	return status;
}

RegistryNotify::~RegistryNotify()
{
	if (!m_bInitSuccess)
	{
		return;
	}

	NTSTATUS status{ STATUS_SUCCESS };
	status = CmUnRegisterCallback(m_Cookie);
	if (NT_SUCCESS(status))
	{
		m_bInitSuccess = FALSE;
	}
}

NTSTATUS RegistryNotify::Init()
{
	NTSTATUS status{ STATUS_SUCCESS };

	if (TRUE == m_bInitSuccess)
	{
		return status;
	}

	UNICODE_STRING usCallbackAltitude = {};
	RtlInitUnicodeString(&usCallbackAltitude, L"38325");

	status = CmRegisterCallbackEx(NotifyOnRegistryActions,
		&usCallbackAltitude,
		g_pGlobalData->pDriverObject,
		nullptr,
		&m_Cookie,
		nullptr);
	if (NT_SUCCESS(status))
	{
		m_bInitSuccess = TRUE;
	}


	return status;
}

NTSTATUS 
RegistryNotify::NotifyOnRegistryActions(
	_In_ PVOID CallbackContext, 
	_In_opt_ PVOID Argument1, 
	_In_opt_ PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	UNREFERENCED_PARAMETER(Argument2);
	NTSTATUS status{ STATUS_SUCCESS };

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return status;
	}

	auto eNotifyClass = static_cast<REG_NOTIFY_CLASS>((ULONG_PTR)Argument1);

	typedef struct _BASE_REG_KEY_INFO
	{
		PVOID		pObject;
		PVOID		reserved;
		// 
	} BASE_REG_KEY_INFO, * PBASE_REG_KEY_INFO;

	HANDLE	hPid = PsGetCurrentProcessId();
	BOOLEAN bAllowed = FALSE;

	switch (eNotifyClass)
	{

		//case RegNtPreOpenKey:
		//case RegNtPreOpenKeyEx:
		//
		//case RegNtPreCreateKey:
		//case RegNtPreCreateKeyEx:

	case RegNtPreDeleteKey:
	case RegNtPreRenameKey:
	case RegNtPreSetValueKey:
	case RegNtPreDeleteValueKey:
	{
		PBASE_REG_KEY_INFO pkeyInfo = reinterpret_cast<PBASE_REG_KEY_INFO>(Argument2);
		if (!pkeyInfo)
		{
			status = STATUS_SUCCESS;
			break;
		}

		bAllowed = AllowedRegistryOperation(hPid, pkeyInfo->pObject);
		if (!bAllowed)
		{
			status = STATUS_ACCESS_DENIED;
			break;
		}

	}
	break;

	default:
		break;
	}

	return status;
}

BOOLEAN 
RegistryNotify::AllowedRegistryOperation(
	IN CONST HANDLE Pid, 
	IN CONST PVOID RegObject)
{
	BOOLEAN bAllow = TRUE;

	BOOLEAN bTrustProcess = FALSE;
	BOOLEAN bProtectRegistry = FALSE;

	WCHAR wszRegistryPath[MAX_REGISTRYPATH]{ 0 };
	bProtectRegistry = KGetRegistryPath(RegObject, wszRegistryPath, MAX_REGISTRYPATH * sizeof(WCHAR));
	if (!bProtectRegistry)
	{
		bAllow = TRUE;
		return bAllow;
	}
	std::wstring wstrRegistryPath{ wszRegistryPath };
	bProtectRegistry = rules->IsInProtectRegistry(wstrRegistryPath);

	// trust process
	WCHAR wszProcessPath[MAX_PATH]{ 0 };
	auto status = GetProcessImageByPid(Pid, wszProcessPath);
	if (!NT_SUCCESS(status) &&
		!bProtectRegistry)
	{
		bAllow = TRUE;
		return bAllow;
	}
	std::wstring wstrTrustProcess{ wszProcessPath };
	bTrustProcess = rules->IsTrusProcess(wstrTrustProcess);

	if (bProtectRegistry &&
		!bTrustProcess)
	{
		bAllow = FALSE;
	}

	return bAllow;
}

ObjectNotify::~ObjectNotify()
{
	if (FALSE == m_bObjectRegisterCreated)
	{
		return;
	}

	if (TRUE == m_bObjectRegisterCreated)
	{
		ObUnRegisterCallbacks(m_hObRegisterCallbacks);
		m_hObRegisterCallbacks = nullptr;
	}

	m_bObjectRegisterCreated = FALSE;
}

NTSTATUS ObjectNotify::Init()
{
	NTSTATUS status{ STATUS_UNSUCCESSFUL };

	OB_OPERATION_REGISTRATION stObOpReg[2] = {};
	OB_CALLBACK_REGISTRATION stObCbReg = {};

	USHORT OperationRegistrationCount = 0;

	do
	{
		if (TRUE == m_bObjectRegisterCreated)
		{
			status = STATUS_SUCCESS;
			break;
		}

		// Processes callbacks
		stObOpReg[OperationRegistrationCount].ObjectType = PsProcessType;
		stObOpReg[OperationRegistrationCount].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		stObOpReg[OperationRegistrationCount].PreOperation = ProcessPreOperationCallback;	// 
		OperationRegistrationCount += 1;

		stObOpReg[OperationRegistrationCount].ObjectType = PsThreadType;
		stObOpReg[OperationRegistrationCount].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		stObOpReg[OperationRegistrationCount].PreOperation = ThreadPreOperationCallback;

		stObCbReg.Version = OB_FLT_REGISTRATION_VERSION;
		stObCbReg.OperationRegistrationCount = OperationRegistrationCount;
		stObCbReg.OperationRegistration = stObOpReg;
		RtlInitUnicodeString(&stObCbReg.Altitude, L"1000");

		status = ObRegisterCallbacks(&stObCbReg, &m_hObRegisterCallbacks);
		if (NT_SUCCESS(status))
		{
			m_bObjectRegisterCreated = TRUE;
		}

	} while (FALSE);


	return status;
}

OB_PREOP_CALLBACK_STATUS 
ObjectNotify::ProcessPreOperationCallback(
	PVOID RegistrationContext, 
	POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// 没有开启进程保护
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return OB_PREOP_SUCCESS;
	}

	// Skip if access is from kernel
	if (OperationInformation->KernelHandle)
	{
		return OB_PREOP_SUCCESS;
	}

	if (!(PEPROCESS)OperationInformation->Object)
	{
		return OB_PREOP_SUCCESS;
	}

	// 增加一些验证
	// 验证是否是进程类型
	if (*PsProcessType != OperationInformation->ObjectType)
	{
		return OB_PREOP_SUCCESS;
	}

	// Accessor
	auto hInitiatorPid = PsGetCurrentProcessId();

	if (hInitiatorPid <= ULongToHandle(4))
	{
		return OB_PREOP_SUCCESS;
	}

	// Target Object
	auto hTargetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);

	// Destination process
	HANDLE			hDstPid = nullptr;
	ACCESS_MASK* pDesiredAccess = nullptr;
	ACCESS_MASK     originalAccess = 0;
	if (OB_OPERATION_HANDLE_CREATE == OperationInformation->Operation)
	{
		hDstPid = hInitiatorPid;
		pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

		originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
	}
	else if (OB_OPERATION_HANDLE_DUPLICATE == OperationInformation->Operation)
	{
		auto& pInfo = OperationInformation->Parameters->DuplicateHandleInformation;
		hDstPid = PsGetProcessId((PEPROCESS)pInfo.TargetProcess);
		pDesiredAccess = &pInfo.DesiredAccess;
		originalAccess = pInfo.OriginalDesiredAccess;
	}
	else
	{
		return OB_PREOP_SUCCESS;
	}

	// skip self
	if (hInitiatorPid == hTargetPid)
	{
		return OB_PREOP_SUCCESS;
	}

	WCHAR wszTargetProcess[MAX_PATH]{ 0 };
	PUNICODE_STRING pCurrentProcessPath{ nullptr };
	NTSTATUS status{ STATUS_SUCCESS };

	ProcessInfo* processInfo = processCtx->FindProcessCtxByPid(hTargetPid);
	if (processInfo && processInfo->ProcessPath.size())
	{
		if ((processInfo->ProcessPath.size() * sizeof(WCHAR)) < sizeof(wszTargetProcess))
		{
			RtlCopyMemory(wszTargetProcess, 
				processInfo->ProcessPath.c_str(), 
				processInfo->ProcessPath.length() * sizeof(WCHAR));
		}
	}
	else
	{
		status = GetProcessImageByPid(hTargetPid, wszTargetProcess);
		if (!NT_SUCCESS(status))
		{
			return OB_PREOP_SUCCESS;
		}
	}


	status = SeLocateProcessImageName(PsGetCurrentProcess(), &pCurrentProcessPath);
	if (!NT_SUCCESS(status) && !pCurrentProcessPath)
	{
		return OB_PREOP_SUCCESS;
	}

	// 针对对目标进程lsass.exe读内存的操作
	// 如果当前进程是非法进程对lsass.exe进程进行操作
	{
		if (KWstrnstr(wszTargetProcess, L"lsass.exe"))
		{
			if (!IsProtectedProcess(PsGetCurrentProcess()))
			{
				if (FlagOn(originalAccess, PROCESS_VM_READ))
				{
					// 如果是非保护进程操作
					// 无耻的话可以结束非保护进程
					*pDesiredAccess |= PROCESS_TERMINATE;

					// 不建议在这里进行
					// 可能会遇到APC_LEVEL无法执行Zw*(BSOD)
					// 考虑ProcessNotify过滤
					KTerminateProcess(HandleToULong(PsGetCurrentProcessId()));
				}
			}
		}
	}

	if (FlagOn(originalAccess, PROCESS_TERMINATE))
	{
		// testing
		std::wstring wstrTargetProcess{ wszTargetProcess };
		//std::transform(wstrTargetProcess.begin(), wstrTargetProcess.end(), wstrTargetProcess.begin(), std::towupper);
		if (rules->IsProtectProcess(wstrTargetProcess))
		{
			*pDesiredAccess &= ~PROCESS_TERMINATE;
		}

	}


	if (pCurrentProcessPath)
	{
		ExFreePool(pCurrentProcessPath);
		pCurrentProcessPath = nullptr;
	}

	/*
	* TODO...
	*/

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS 
ObjectNotify::ThreadPreOperationCallback(
	PVOID RegistrationContext, 
	POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (!MmIsAddressValid(OperationInformation->Object))
	{
		return OB_PREOP_SUCCESS;
	}

	if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE)
	{
		return OB_PREOP_SUCCESS;
	}

	// 换一种写法
	if (ExGetPreviousMode() == KernelMode)
	{
		return OB_PREOP_SUCCESS;
	}

	// Accessor
	auto hInitiatorPid = PsGetCurrentProcessId();

	if (hInitiatorPid <= ULongToHandle(4))
	{
		return OB_PREOP_SUCCESS;
	}


	// Target Object
	auto			hTargetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);

	// Destination process
	HANDLE			hDstPid = nullptr;

	ACCESS_MASK* pDesiredAccess = nullptr;

	if (OB_OPERATION_HANDLE_CREATE == OperationInformation->Operation)
	{
		hDstPid = hInitiatorPid;
		pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
	}
	else if (OB_OPERATION_HANDLE_DUPLICATE == OperationInformation->Operation)
	{
		auto& pInfo = OperationInformation->Parameters->DuplicateHandleInformation;
		hDstPid = PsGetProcessId((PEPROCESS)pInfo.TargetProcess);
		pDesiredAccess = &pInfo.DesiredAccess;
	}
	else
	{
		return OB_PREOP_SUCCESS;
	}

	// skip self
	if (hInitiatorPid == hTargetPid)
	{
		return OB_PREOP_SUCCESS;
	}

	WCHAR wszTargetProcess[MAX_PATH]{ 0 };
	BOOLEAN bProtectd = FALSE;
	ProcessInfo* processInfo = processCtx->FindProcessCtxByPid(hTargetPid);
	if (processInfo && processInfo->ProcessPath.size())
	{
		bProtectd = processInfo->bProtected;
	}
	else
	{
		auto status = GetProcessImageByPid(hTargetPid, wszTargetProcess);
		if (!NT_SUCCESS(status))
		{
			return OB_PREOP_SUCCESS;
		}
		std::wstring wstrTargetProcess{ wszTargetProcess };
		bProtectd = rules->IsProtectProcess(wstrTargetProcess);
	}

	if (FlagOn(*pDesiredAccess, THREAD_TERMINATE))
	{
		if (bProtectd)
		{
			*pDesiredAccess &= ~THREAD_TERMINATE;
		}
	}

	return OB_PREOP_SUCCESS;
}
