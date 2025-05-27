#include "Imports.hpp"

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
	);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

// public exports from ntoskrnl.exe
EXTERN_C
{
NTSYSAPI
VOID
NTAPI
KeInitializeApc(
	OUT PRKAPC Apc,
	IN PRKTHREAD Thread,
	IN KAPC_ENVIRONMENT Environment,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
	IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
	IN KPROCESSOR_MODE ApcMode OPTIONAL,
	IN PVOID NormalContext OPTIONAL
);

NTSYSAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	IN PRKAPC Apc,
	IN PVOID SystemArgument1 OPTIONAL,
	IN PVOID SystemArgument2 OPTIONAL,
	IN KPRIORITY Increment
);

NTSTATUS
NTSYSAPI
NTAPI
ZwGetNextThread(
	HANDLE ProcessHandle,
	HANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Flags,
	PHANDLE NewThreadHandle
);
};

typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	union
	{
		UNICODE_STRING		path;
		UNICODE_STRING32	path32;;
	};

	wchar_t buffer[488];
	PVOID module;
	ULONG complete;
	NTSTATUS status;
} INJECT_BUFFER, * PINJECT_BUFFER;

VOID
NTAPI
ApcInjectWow64Process(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo,
	PUNICODE_STRING InjectDllPath);

VOID
NTAPI
ApcInjectNativeProcess(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo,
	PUNICODE_STRING InjectDllPath);