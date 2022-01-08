/*
VEH misuse detector for Microsoft Windows

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/DetectWindowsCopyOnWriteForAPI

Released under AGPL see LICENSE for more information
*/

#pragma once

#include "stdafx.h"
#include "InternalStructs.h"
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Winternl.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <strsafe.h>
#include <winevt.h> 
#include <evntprov.h>

//
extern bool	bFirstRun;
extern bool bConsole;
extern bool	bService;

// Reimplement from Winternal.h
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT DWORD_PTR* ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

// Used for ProcessCookie stuff using a different version
// of the ProcessInfoClass
typedef NTSTATUS(WINAPI* _MyNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN MYPROCESSINFOCLASS ProcessInformationClass,
	OUT DWORD_PTR* ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

// From ReactOS
struct VEH_ENTRY_VISTA
{
	VEH_ENTRY_VISTA* Flink;
	VEH_ENTRY_VISTA* Blink;
};

// From ReactOS
#pragma pack(2)
struct VEH_HANDLER_ENTRY
{
	LIST_ENTRY Entry;
	PVOID VectoredHandler;
	PVOID VectoredHandler2;
	PVOID VectoredHandler3;
};

typedef struct _VECTORED_HANDLER_LIST_OW {
	void* mutex_exception;
	VEH_ENTRY_VISTA* first_exception_handler;
	VEH_ENTRY_VISTA* last_exception_handler;
	void* mutex_continue;
	VEH_ENTRY_VISTA* first_continue_handler;
	VEH_ENTRY_VISTA* last_continue_handler;
} VECTORED_HANDLER_LIST_OW;


// VEH Stuff
typedef struct _VECTORED_HANDLER_ENTRY {
	_VECTORED_HANDLER_ENTRY* next;
	_VECTORED_HANDLER_ENTRY* previous;
	ULONG refs;
	PVECTORED_EXCEPTION_HANDLER handler;
} VECTORED_HANDLER_ENTRY;


typedef struct _VECTORED_HANDLER_LIST {
	void* mutex_exception;
	VECTORED_HANDLER_ENTRY* first_exception_handler;
	VECTORED_HANDLER_ENTRY* last_exception_handler;
	void* mutex_continue;
	VECTORED_HANDLER_ENTRY* first_continue_handler;
	VECTORED_HANDLER_ENTRY* last_continue_handler;
} VECTORED_HANDLER_LIST;

// http://downloads.securityfocus.com/vulnerabilities/exploits/26556.c
typedef PIMAGE_NT_HEADERS(NTAPI* RTLIMAGENTHEADER)(DWORD_PTR);




