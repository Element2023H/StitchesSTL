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
	m_listOfProtectProcess.push_back(ProcessPath);
}

void Rules::DelProtectProcess(std::wstring& ProcessPath)
{
	m_listOfProtectProcess.erase(std::find(m_listOfProtectProcess.begin(), m_listOfProtectProcess.end(), ProcessPath));
}

BOOLEAN 
Rules::IsProtectProcess(std::wstring& ProcessPath)
{
	return std::find(m_listOfProtectProcess.begin(), m_listOfProtectProcess.end(), ProcessPath) != m_listOfProtectProcess.end();
}

void Rules::AddTrustProcess(std::wstring& ProcessPath)
{
	m_listOfTrustProcess.push_back(ProcessPath);
}

void Rules::DelTrustProcess(std::wstring& ProcessPath)
{
	m_listOfTrustProcess.erase(std::find(m_listOfTrustProcess.begin(), m_listOfTrustProcess.end(), ProcessPath));
}

BOOLEAN Rules::IsTrusProcess(std::wstring& ProcessPath)
{
	return std::find(m_listOfTrustProcess.begin(), m_listOfTrustProcess.end(), ProcessPath) != m_listOfTrustProcess.end();
}

void Rules::AddProtectDir(std::wstring& FileName)
{
	m_listOfProtectDir.push_back(FileName);
}

void Rules::DelProtectDir(std::wstring& FileName)
{
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

