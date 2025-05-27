#include "KUtils.hpp"
#include "Lazy.hpp"
#include "GlobalData.hpp"

#define _CRT_SECURE_NO_WARNINGS

extern Stitches::LazyInstance<GlobalData, NonPagedPoolNx> g_pGlobalData;;

constexpr ULONG MEM_ALLOC_TAG = 'htaP';
constexpr ULONG REGISTRY_MEM_TAG = 'mtsR';

#ifndef SYSTEM_PROCESS_NAME
#define SYSTEM_PROCESS_NAME L"System"
#endif

#ifndef MAX_PROCESS_IMAGE_LENGTH
#define MAX_PROCESS_IMAGE_LENGTH	520
#endif

#ifndef MAX_REGISTRY_PATH_LENGTH
#define MAX_REGISTRY_PATH_LENGTH	(512 * sizeof(WCHAR))
#endif

WCHAR*
KWstrnstr(
	const WCHAR* src,
	const WCHAR* find)
{
	WCHAR* cp = (WCHAR*)src;
	WCHAR* s1 = NULL, * s2 = NULL;

	if (NULL == src ||
		NULL == find)
	{
		return NULL;
	}

	while (*cp)
	{
		s1 = cp;
		s2 = (WCHAR*)find;

		while (*s2 && *s1 && !(towlower(*s1) - towlower(*s2)))
		{
			s1++, s2++;
		}

		if (!(*s2))
		{
			return cp;
		}

		cp++;
	}
	return NULL;
}

static
NTSTATUS
KQuerySymbolicLink(
	IN  PUNICODE_STRING SymbolicLinkName,
	OUT PWCHAR			SymbolicLinkTarget)
{
	if (!SymbolicLinkName)
	{
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS            status = STATUS_SUCCESS;
	HANDLE              hLink = NULL;
	OBJECT_ATTRIBUTES   oa{};
	UNICODE_STRING		LinkTarget{};
	// ����Ҳ������
	InitializeObjectAttributes(&oa, SymbolicLinkName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);

	// ͨ�������ȴ򿪷�������
	status = ZwOpenSymbolicLinkObject(&hLink, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status) || !hLink)
	{
		return status;
	}

	// �����ڴ�
	LinkTarget.Length = MAX_PATH * sizeof(WCHAR);
	LinkTarget.MaximumLength = LinkTarget.Length + sizeof(WCHAR);
	LinkTarget.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, LinkTarget.MaximumLength, MEM_ALLOC_TAG);
	if (!LinkTarget.Buffer)
	{
		ZwClose(hLink);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget.Buffer, LinkTarget.MaximumLength);

	// ��ȡ����������
	status = ZwQuerySymbolicLinkObject(hLink, &LinkTarget, NULL);
	if (NT_SUCCESS(status))
	{
		RtlCopyMemory(SymbolicLinkTarget, LinkTarget.Buffer, wcslen(LinkTarget.Buffer) * sizeof(WCHAR));
	}
	if (LinkTarget.Buffer)
	{
		ExFreePoolWithTag(LinkTarget.Buffer, MEM_ALLOC_TAG);
	}

	if (hLink)
	{
		ZwClose(hLink);
		hLink = nullptr;
	}


	return status;
}

// �豸·��תdos·��
// ԭ����ö�ٴ�a��z�̵��豸Ŀ¼,Ȼ��ͨ��ZwOpenSymbolicLinkObject
// ����ȡ���豸��Ӧ�ķ�������,ƥ���ϵĻ�,�������Ӿ����̷�
NTSTATUS
KGetDosProcessPath(
	IN	PWCHAR DeviceFileName,
	OUT PWCHAR DosFileName)
{
	NTSTATUS			status = STATUS_SUCCESS;
	WCHAR				DriveLetter{};
	WCHAR				DriveBuffer[30] = L"\\??\\C:";
	UNICODE_STRING		DriveLetterName{};
	WCHAR				LinkTarget[260]{};

	RtlInitUnicodeString(&DriveLetterName, DriveBuffer);

	DosFileName[0] = 0;

	// �� a �� z��ʼö�� һ��������
	for (DriveLetter = L'A'; DriveLetter <= L'Z'; DriveLetter++)
	{
		// �滻�̷�
		DriveLetterName.Buffer[4] = DriveLetter;

		// ͨ���豸����ȡ����������
		status = KQuerySymbolicLink(&DriveLetterName, LinkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		// �ж��豸�Ƿ���ƥ��,ƥ���ϵĻ�����,���п�������
		if (_wcsnicmp(DeviceFileName, LinkTarget, wcslen(LinkTarget)) == 0)
		{
			wcscpy(DosFileName, DriveLetterName.Buffer + 4);
			wcscat(DosFileName, DeviceFileName + wcslen(LinkTarget));
			break;
		}
	}
	return status;
}

NTSTATUS
GetProcessImageByPid(
	IN CONST HANDLE Pid,
	IN OUT PWCHAR ProcessImage)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pEprocess = NULL;
	HANDLE hProcess = NULL;
	PVOID pProcessPath = NULL;

	ULONG uProcessImagePathLength = 0;

	if (!ProcessImage || Pid < (ULongToHandle)(4))
	{
		return STATUS_INVALID_PARAMETER;
	}

	// �޸���bug
	if (Pid == (ULongToHandle)(4))
	{
		RtlCopyMemory(ProcessImage, SYSTEM_PROCESS_NAME, sizeof(SYSTEM_PROCESS_NAME));
		return status;
	}

	status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	__try
	{
		do
		{
			status = ObOpenObjectByPointer(pEprocess,
				OBJ_KERNEL_HANDLE,
				NULL,
				PROCESS_ALL_ACCESS,
				*PsProcessType,
				KernelMode,
				&hProcess);
			if (!NT_SUCCESS(status))
			{
				break;
			}
			//__TIME__

			// ��ȡ����
			// https://learn.microsoft.com/zh-cn/windows/win32/procthread/zwqueryinformationprocess
			status = ZwQueryInformationProcess(hProcess,
				ProcessImageFileName,
				NULL,
				0,
				&uProcessImagePathLength);
			if (STATUS_INFO_LENGTH_MISMATCH == status)
			{
				// ���볤��+sizeof(UNICODE_STRING)Ϊ�˰�ȫ���
				pProcessPath = ExAllocatePoolWithTag(NonPagedPool,
					uProcessImagePathLength + sizeof(UNICODE_STRING),
					MEM_ALLOC_TAG);
				if (pProcessPath)
				{
					RtlZeroMemory(pProcessPath, uProcessImagePathLength + sizeof(UNICODE_STRING));

					// ��ȡ����
					status = ZwQueryInformationProcess(hProcess,
						ProcessImageFileName,
						pProcessPath,
						uProcessImagePathLength,
						&uProcessImagePathLength);
					if (!NT_SUCCESS(status))
					{
						break;
					}

					status = KGetDosProcessPath(reinterpret_cast<PUNICODE_STRING>(pProcessPath)->Buffer, ProcessImage);
					if (!NT_SUCCESS(status))
					{
						break;
					}
				}
			}// end if (STATUS_INFO_LENGTH_MISMATCH == status)
		} while (FALSE);
	}
	__finally
	{

		if (pProcessPath)
		{
			ExFreePoolWithTag(pProcessPath, MEM_ALLOC_TAG);
			pProcessPath = NULL;
		}


		if (hProcess)
		{
			ZwClose(hProcess);
			hProcess = NULL;
		}
	}

	ObDereferenceObject(pEprocess);

	return status;
}


NTSTATUS
GetProcessImage(
	IN CONST PEPROCESS Process,
	IN OUT PWCHAR ProcessImage)
{
	if (!ProcessImage || !Process)
	{
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	HANDLE hProcess = nullptr;

	ULONG uProcessImagePathLength = 0;
	PVOID pProcessPath = nullptr;

	__try
	{
		do
		{
			status = ObOpenObjectByPointer(Process,
				OBJ_KERNEL_HANDLE,
				nullptr,
				PROCESS_ALL_ACCESS,
				*PsProcessType,
				KernelMode,
				&hProcess);

			if (!NT_SUCCESS(status) || !hProcess)
			{
				break;
			}

			// ��ȡ����
			// https://learn.microsoft.com/zh-cn/windows/win32/procthread/zwqueryinformationprocess
			status = ZwQueryInformationProcess(hProcess,
				ProcessImageFileName,
				nullptr,
				0,
				&uProcessImagePathLength);
			if (STATUS_INFO_LENGTH_MISMATCH == status)
			{
				// ���볤��+sizeof(UNICODE_STRING)Ϊ�˰�ȫ���
				pProcessPath = ExAllocatePoolWithTag(NonPagedPool,
					uProcessImagePathLength + sizeof(UNICODE_STRING),
					MEM_ALLOC_TAG);
				if (pProcessPath)
				{
					RtlZeroMemory(pProcessPath, uProcessImagePathLength + sizeof(UNICODE_STRING));

					// ��ȡ����
					status = ZwQueryInformationProcess(hProcess,
						ProcessImageFileName,
						pProcessPath,
						uProcessImagePathLength,
						&uProcessImagePathLength);
					if (!NT_SUCCESS(status))
					{
						break;
					}

					status = KGetDosProcessPath(reinterpret_cast<PUNICODE_STRING>(pProcessPath)->Buffer, ProcessImage);
					if (!NT_SUCCESS(status))
					{
						break;
					}

					//RtlCopyMemory(ProcessImage, pUstrProcessName->Buffer, pUstrProcessName->Length);
				}
			}// end if (STATUS_INFO_LENGTH_MISMATCH == status)
		} while (FALSE);
	}
	__finally
	{

		if (pProcessPath)
		{
			ExFreePoolWithTag(pProcessPath, MEM_ALLOC_TAG);
			pProcessPath = nullptr;
		}


		if (hProcess)
		{
			ZwClose(hProcess);
			hProcess = nullptr;
		}
	}

	// �Ͻ�
	if (Process)
	{
		ObDereferenceObject(Process);
	}

	return status;
}


//************************************
// Method:    UnicodeStringContains
// FullName:  UnicodeStringContains
// Access:    public 
// Returns:   BOOLEAN
// Qualifier:
// Parameter: PUNICODE_STRING UnicodeString
// Parameter: PCWSTR SearchString
// https://github.com/Xacone/BestEdrOfTheMarket/blob/main/BestEdrOfTheMarketDriver/src/Utils.cpp
//************************************
BOOLEAN
UnicodeStringContains(
	PUNICODE_STRING UnicodeString,
	PCWSTR          SearchString)
{

	if (UnicodeString == NULL ||
		UnicodeString->Buffer == NULL ||
		SearchString == NULL)
	{
		return FALSE;
	}

	size_t searchStringLength = wcslen(SearchString);
	if (searchStringLength == 0)
	{
		return FALSE;
	}

	USHORT unicodeStringLengthInChars = UnicodeString->Length / sizeof(WCHAR);

	if (unicodeStringLengthInChars < searchStringLength)
	{
		return FALSE;
	}

	for (USHORT i = 0; i <= unicodeStringLengthInChars - searchStringLength; i++)
	{
		if (!MmIsAddressValid(&UnicodeString->Buffer[i]))
		{
			return FALSE;
		}

		if (wcsncmp(&UnicodeString->Buffer[i], SearchString, searchStringLength) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN
IsProtectedProcess(IN CONST PEPROCESS Process)
{
	if (!Process)
	{
		return FALSE;
	}

	if (g_pGlobalData->PsIsProtectedProcess)
	{
		return (g_pGlobalData->PsIsProtectedProcess(Process) != 0);
	}
	else if (g_pGlobalData->PsIsProtectedProcessLight(Process))
	{
		return (g_pGlobalData->PsIsProtectedProcessLight(Process) != 0);
	}

	return FALSE;
}


_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
KTerminateProcess(IN CONST ULONG ProcessId)
{
	if (ProcessId <= 4 ||
		KeGetCurrentIrql > PASSIVE_LEVEL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	HANDLE hProcess = nullptr;
	OBJECT_ATTRIBUTES oa{};
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (!g_pGlobalData->ZwTerminateProcess)
	{
		UNICODE_STRING ustrZwTerminateProcess{};
		RtlInitUnicodeString(&ustrZwTerminateProcess, ZWTERMINATEPROCESS);

		// �ٴλ�ȡ�µ�ַ
		g_pGlobalData->ZwTerminateProcess.Init(L"ZwTerminateProcess");
		if (!g_pGlobalData->ZwTerminateProcess)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	__try
	{
		oa.Length = sizeof(OBJECT_ATTRIBUTES);
		InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		CLIENT_ID clientId{};
		clientId.UniqueProcess = (ULongToHandle)(ProcessId);

		status = ZwOpenProcess(&hProcess, 1, &oa, &clientId);

		// ��ȡ���̾��
		if (NT_SUCCESS(status))
		{
			status = g_pGlobalData->ZwTerminateProcess(hProcess, STATUS_SUCCESS);
		}
	}
	__finally
	{
		if (hProcess)
		{
			ZwClose(hProcess);
			hProcess = nullptr;
		}
	}
	return status;
}

BOOLEAN
KGetRegistryPath(
	IN PVOID RegistryObject,
	IN OUT PWCHAR Buffer,
	IN CONST ULONG BufferSize)
{
	if (!RegistryObject ||
		!Buffer ||
		!BufferSize ||
		!MmIsAddressValid(RegistryObject))
	{
		return FALSE;
	}

	if (KeGetCurrentIrql() > PASSIVE_LEVEL ||
		PsGetCurrentProcessId() <= ULongToHandle(4))
	{
		return FALSE;
	}

	BOOLEAN bResult{ FALSE };

	ULONG nAllocSize = sizeof(UNICODE_STRING) + MAX_REGISTRY_PATH_LENGTH;
	PUNICODE_STRING pObjectName = reinterpret_cast<PUNICODE_STRING>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocSize, REGISTRY_MEM_TAG));
	if (pObjectName)
	{
		RtlZeroMemory(pObjectName, nAllocSize);
		pObjectName->Length = MAX_REGISTRY_PATH_LENGTH;
		pObjectName->MaximumLength = MAX_REGISTRY_PATH_LENGTH + sizeof(WCHAR);

		ULONG nReturnLength = 0;
		auto status = ObQueryNameString(RegistryObject,
			reinterpret_cast<POBJECT_NAME_INFORMATION>(pObjectName),
			nAllocSize,
			&nReturnLength);
		if (NT_SUCCESS(status) &&
			BufferSize > nReturnLength)
		{
			status = RtlStringCbCopyUnicodeString(Buffer, nReturnLength, pObjectName);
			bResult = NT_SUCCESS(status);
		}

		ExFreePoolWithTag(pObjectName, REGISTRY_MEM_TAG);
		pObjectName = nullptr;
	}
	else
	{
		return bResult;
	}


	return bResult;
}
