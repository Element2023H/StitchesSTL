#pragma once
#include "Imports.hpp"
#include "Lazy.hpp"


class NotifyBase 
{
public:
	NotifyBase() = default;
	virtual ~NotifyBase() = default;

	virtual NTSTATUS Init() { return STATUS_SUCCESS; }
};

class ThreadNotify : public NotifyBase
{
public:
	ThreadNotify() = default;
	~ThreadNotify();

	ThreadNotify(const ThreadNotify&) = delete;
	ThreadNotify(ThreadNotify&&) = delete;
	ThreadNotify& operator=(const ThreadNotify&) = delete;

	NTSTATUS Init() override;

protected:
	static VOID ThreadNotifyRoutine(
		IN HANDLE ProcessId,
		IN HANDLE ThreadId,
		IN BOOLEAN Create);

private:
	BOOLEAN		m_bInitialized{ FALSE };
};

class ProcessNotify : public NotifyBase
{
public:
	ProcessNotify() = default;
	~ProcessNotify();

	ProcessNotify(const ProcessNotify&) = delete;
	ProcessNotify(ProcessNotify&&) = delete;
	ProcessNotify& operator=(const ProcessNotify&) = delete;

	NTSTATUS Init() override;

protected:
	static VOID ProcessNotifyRoutine(
		IN OUT				PEPROCESS Process,
		IN OUT				HANDLE ProcessId,
		IN OUT OPTIONAL		PPS_CREATE_NOTIFY_INFO CreateInfo);

private:
	BOOLEAN		m_bInitialized{ FALSE };
};

class ImageNotify : public NotifyBase
{
public:
	ImageNotify() = default;
	~ImageNotify();

	ImageNotify(const ImageNotify&) = delete;
	ImageNotify(ImageNotify&&) = delete;
	ImageNotify& operator=(const ImageNotify&) = delete;

	NTSTATUS Init() override;

protected:
	static VOID ImageNotifyRoutine(
		_In_  PUNICODE_STRING FullImageName,
		_In_  HANDLE ProcessId,
		_In_  PIMAGE_INFO ImageInfo);

private:
	BOOLEAN		m_bInitialized{ FALSE };
};



class NotifyRoutines
{
public:
	NotifyRoutines() = default;
	~NotifyRoutines() = default;

	NTSTATUS Init();

private:
	ProcessNotify	m_ProcessNotify;
	ThreadNotify	m_ThreadNotify;
	ImageNotify		m_ImageNotify;
};
static Stitches::LazyInstance<NotifyRoutines, NonPagedPoolNx> notifyRoutines;

