#pragma once
#include "Locks.hpp"
#include <list>
#include <xstring>
#include "Rule.hpp"
#include "Lazy.hpp"

struct ProcessInfo
{
	ProcessInfo()	= default;
	~ProcessInfo()	= default;

	HANDLE			Pid;
	std::wstring	ProcessPath;
	std::wstring	ProcessCmdLine;
	BOOLEAN			bProtected;
	BOOLEAN			bIsWow64;
	BOOLEAN			bTrusted;
};

class ProcessCtx
{
public:
	ProcessCtx() = default;
	~ProcessCtx();

	VOID
	AddProcessContext(
		IN CONST PEPROCESS Process,
		IN CONST HANDLE Pid,
		IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo);

	VOID
	DeleteProcessCtxByPid(IN CONST HANDLE ProcessId);

	ProcessInfo*
	FindProcessCtxByPid(IN CONST HANDLE Pid);


private:
	Stitches::fast_mutex	m_lock;
	std::list<ProcessInfo>	m_ListOfProcessCtx;
};

static Stitches::LazyInstance<ProcessCtx, NonPagedPoolNx> processCtx;