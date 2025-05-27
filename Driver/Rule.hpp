#pragma once
#include <list>
#include <xstring>
#include "Imports.hpp"
#include "Lazy.hpp"

class Rules
{
public:
	Rules() = default;
	~Rules();

	void	AddProtectProcess( std::wstring& ProcessPath);
	void	DelProtectProcess( std::wstring& ProcessPath);
	BOOLEAN IsProtectProcess( std::wstring& ProcessPath);

	void	AddTrustProcess( std::wstring& ProcessPath);
	void	DelTrustProcess( std::wstring& ProcessPath);
	BOOLEAN IsTrusProcess( std::wstring& ProcessPath);

	void	AddProtectDir(std::wstring& );
	void	DelProtectDir(std::wstring& );
	BOOLEAN IsInProtectDir(std::wstring& );
private:
	std::list<std::wstring> m_listOfProtectProcess;
	std::list<std::wstring> m_listOfTrustProcess;
	std::list<std::wstring> m_listOfProtectDir;
};

static Stitches::LazyInstance<Rules, NonPagedPoolNx> rules;
