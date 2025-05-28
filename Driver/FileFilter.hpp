#pragma once
#include "Lazy.hpp"
#include "Imports.hpp"

class FileFilter
{
public:
	FileFilter() = default;
	~FileFilter();

	NTSTATUS Init();

private:
	PFLT_FILTER m_pFileFilter{ nullptr };
	BOOLEAN m_bInitSuccess{ FALSE };
};
static Stitches::LazyInstance<FileFilter, NonPagedPoolNx> fileFilter;
