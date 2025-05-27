#include "ProcessCtx.hpp"
#include "KUtils.hpp"
#include "Lazy.hpp"
#include "GlobalData.hpp"
#include "Rule.hpp"

using namespace Stitches;

extern LazyInstance<GlobalData, NonPagedPoolNx> g_pGlobalData;;

ProcessCtx::~ProcessCtx()
{
	m_ListOfProcessCtx.clear();
}

VOID 
ProcessCtx::AddProcessContext(
	IN CONST PEPROCESS Process, 
	IN CONST HANDLE Pid,
	IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UniqueLock<fast_mutex> _lock(m_lock);

	
	ProcessInfo processInfo{};
	processInfo.Pid = Pid;
	processInfo.bProtected = IsProtectedProcess(Process);

	if (g_pGlobalData->PsGetProcessWow64Process)
	{
		processInfo.bIsWow64 = (g_pGlobalData->PsGetProcessWow64Process(Process) != nullptr);
	}
	
	processInfo.ProcessPath		= &CreateInfo->ImageFileName->Buffer[sizeof(L"\\??")/2];
	processInfo.ProcessCmdLine	= CreateInfo->CommandLine->Buffer;
	processInfo.bProtected		= rules->IsProtectProcess(processInfo.ProcessPath);
	processInfo.bTrusted		= rules->IsTrusProcess(processInfo.ProcessPath);

	m_ListOfProcessCtx.push_back(processInfo);

}

VOID 
ProcessCtx::DeleteProcessCtxByPid(IN CONST HANDLE ProcessId)
{
	UniqueLock<fast_mutex> _lock(m_lock);
	
	if (m_ListOfProcessCtx.size() == 0)
	{
		return;
	}

	for (auto it = m_ListOfProcessCtx.begin(); it != m_ListOfProcessCtx.end(); ++it )
	{
		if (it->Pid == ProcessId)
		{
			m_ListOfProcessCtx.erase(it);
			break;
		}
	}
}

ProcessInfo*
ProcessCtx::FindProcessCtxByPid(IN CONST HANDLE Pid)
{
	UniqueLock<fast_mutex> _lock(m_lock);
	if (m_ListOfProcessCtx.size() == 0)
	{
		return nullptr;
	}

	ProcessInfo* pProcessInfo{ nullptr };
	
	for (auto it = m_ListOfProcessCtx.begin(); 
		 it != m_ListOfProcessCtx.end();
		 ++it)
	{
		if (it->Pid == Pid)
		{
			pProcessInfo = &(*it);
			break;
		}
	}

	return pProcessInfo;
}
