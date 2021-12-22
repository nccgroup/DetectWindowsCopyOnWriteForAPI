/*
A copy on write detector for Windows APIs across processes

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/DetectWindowsCopyOnWriteForAPI

Released under AGPL see LICENSE for more information
*/

#pragma once

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.     
// 0x0501
#define _WIN32_WINNT 0x0600	// Change this to the appropriate value to target other versions of Windows.
#endif						

#include "stdafx.h"
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
#include "Engine.h"


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

// http://downloads.securityfocus.com/vulnerabilities/exploits/26556.c
typedef PIMAGE_NT_HEADERS(NTAPI* RTLIMAGENTHEADER)(DWORD_PTR);


// http://uninformed.org/index.cgi?v=6&a=3&p=2
//typedef struct _IMAGE_BASE_RELOCATION {
//	ULONG  VirtualAddress;
//	ULONG  SizeOfBlock;
//	USHORT TypeOffset[1];
//} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;