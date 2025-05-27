#include "Rule.hpp"
#include <algorithm>
#include <cwctype>

Rules::~Rules()
{
	m_listOfProtectProcess.clear();
	m_listOfTrustProcess.clear();
	m_listOfProtectDir.clear();
}

void 
Rules::AddProtectProcess(std::wstring& ProcessPath)
{
	std::transform(ProcessPath.begin(), ProcessPath.end(), ProcessPath.begin(), std::towupper);
	m_listOfProtectProcess.push_back(ProcessPath);
}

void Rules::DelProtectProcess(std::wstring& ProcessPath)
{
	std::transform(ProcessPath.begin(), ProcessPath.end(), ProcessPath.begin(), std::towupper);
	m_listOfProtectProcess.erase(std::find(m_listOfProtectProcess.begin(), m_listOfProtectProcess.end(), ProcessPath));
}

BOOLEAN 
Rules::IsProtectProcess(std::wstring& ProcessPath)
{
	std::transform(ProcessPath.begin(), ProcessPath.end(), ProcessPath.begin(), std::towupper);
	return std::find(m_listOfProtectProcess.begin(), m_listOfProtectProcess.end(), ProcessPath) != m_listOfProtectProcess.end();
}

void Rules::AddTrustProcess(std::wstring& ProcessPath)
{
	std::transform(ProcessPath.begin(), ProcessPath.end(), ProcessPath.begin(), std::towupper);
	m_listOfTrustProcess.push_back(ProcessPath);
}

void Rules::DelTrustProcess(std::wstring& ProcessPath)
{
	std::transform(ProcessPath.begin(), ProcessPath.end(), ProcessPath.begin(), std::towupper);
	m_listOfTrustProcess.erase(std::find(m_listOfTrustProcess.begin(), m_listOfTrustProcess.end(), ProcessPath));
}

BOOLEAN Rules::IsTrusProcess(std::wstring& ProcessPath)
{
	std::transform(ProcessPath.begin(), ProcessPath.end(), ProcessPath.begin(), std::towupper);
	return std::find(m_listOfTrustProcess.begin(), m_listOfTrustProcess.end(), ProcessPath) != m_listOfTrustProcess.end();
}

void Rules::AddProtectDir(std::wstring& FileName)
{
	std::transform(FileName.begin(), FileName.end(), FileName.begin(), std::towupper);
	m_listOfProtectDir.push_back(FileName);
}

void Rules::DelProtectDir(std::wstring& FileName)
{
	std::transform(FileName.begin(), FileName.end(), FileName.begin(), std::towupper);
	m_listOfProtectDir.erase(std::find(m_listOfProtectDir.begin(), m_listOfProtectDir.end(), FileName));
}

BOOLEAN Rules::IsInProtectDir(std::wstring& FileName)
{
	std::transform(FileName.begin(), FileName.end(), FileName.begin(), std::towupper);

	for (auto it : m_listOfProtectDir)
	{
		if (FileName.find(it) != std::wstring::npos)
		{
			return TRUE;
		}
	}

	return FALSE;
}

void Rules::AddProtectRegistry(std::wstring& RegistryPath)
{
	m_listOfProtectRegistry.push_back(RegistryPath);
}

void Rules::DelProtectRegistry(std::wstring& RegistryPath)
{
	m_listOfProtectRegistry.erase(std::find(m_listOfProtectRegistry.begin(), m_listOfProtectRegistry.end(), RegistryPath));
}

BOOLEAN Rules::IsInProtectRegistry(std::wstring& RegistryPath)
{
	for (auto it : m_listOfProtectRegistry)
	{
		if (RegistryPath.find(it) != std::wstring::npos)
		{
			return TRUE;
		}
	}

	return FALSE;
}

