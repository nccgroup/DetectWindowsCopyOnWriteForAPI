/*
Debug register (hardware breakpoint) misuse detector for Microsoft Windows

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/

#pragma once


#include "stdafx.h"

// Globals
HANDLE	hProcess;
TCHAR	strErrMsg[1024];
DWORD	dwModuleRelocs = 0;
DWORD	dwCountError = 0;
DWORD	dwCountOK = 0;
DWORD	dwOpen = 0;

// Structures to hold process information
#pragma pack(push, 1)
struct procNfoStuct {
	DWORD PID;
	TCHAR Name[MAX_PATH];
	unsigned long long TotalExecMem = 0;
};
#pragma pack(pop)
procNfoStuct Procs[4098];
DWORD NumOfProcs = 0;


//
// Function	: SetDebugPrivilege
// Role		: Gets privs for our process
// Notes	: 
//
BOOL SetPrivilege(HANDLE hProcess, LPCTSTR lPriv)
{
	LUID luid;
	TOKEN_PRIVILEGES privs;
	HANDLE hToken = NULL;
	DWORD dwBufLen = 0;
	char buf[1024];

	ZeroMemory(&luid, sizeof(luid));

	if (!LookupPrivilegeValue(NULL, lPriv, &luid)) return false;

	privs.PrivilegeCount = 1;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	memcpy(&privs.Privileges[0].Luid, &luid, sizeof(privs.Privileges[0].Luid));


	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
		return false;

	if (!AdjustTokenPrivileges(hToken, FALSE, &privs,
		sizeof(buf), (PTOKEN_PRIVILEGES)buf, &dwBufLen))
		return false;

	CloseHandle(hProcess);
	CloseHandle(hToken);

	return true;
}

/// <summary>
/// Analyze the process and its memory regions
/// </summary>
/// <param name="dwPID">Process ID</param>
void AnalyzeProc(DWORD dwPID)
{
	DWORD dwRet, dwMods;
	HANDLE hProcess;
	HMODULE hModule[4096];
	TCHAR cProcess[MAX_PATH]; // Process name
	BOOL bIsWow64 = FALSE;
	BOOL bIsWow64Other = FALSE;
	DWORD dwRES = 0;


	// Get process handle by hook or by crook
	hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	if (hProcess == NULL)
	{
		if (GetLastError() == 5) {
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
			if (hProcess == NULL) {

				hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
				if (hProcess == NULL) {

					fwprintf(stderr, _TEXT("[!] [%d][UNKNOWN] Failed to OpenProcess - %d\n"), dwPID, GetLastError());
					dwCountError++;
					return;
				}
			}
		}
		else {
			fwprintf(stderr, _TEXT("[!] [%d][UNKNOWN] Failed to OpenProcess - %d\n"), dwPID, GetLastError());
			dwCountError++;
			return;
		}
	}


	// Enumerate the process modules
	if (EnumProcessModules(hProcess, hModule, 4096 * sizeof(HMODULE), &dwRet) == FALSE)
	{
		DWORD dwSz = MAX_PATH;
		if (QueryFullProcessImageName(hProcess, 0, cProcess, &dwSz) == TRUE) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] not analysed %d\n"), dwPID, cProcess, GetLastError());
			dwOpen++;
		}
		else {
			fwprintf(stdout, _TEXT("[i] [%d][%s] not analysed %d\n"), dwPID, _TEXT("UNKNOWN"), GetLastError());
			dwOpen++;
		}

		if (GetLastError() == 299) {
			//fprintf(stderr, "64bit process and we're 32bit - sad panda! skipping PID %d\n", dwPID);
		}
		else {
			//fprintf(stderr, "Error in EnumProcessModules(%d),%d\n", dwPID, GetLastError());
		}

		dwCountError++;
		if (hProcess != NULL)CloseHandle(hProcess);
		return;
	}
	dwMods = dwRet / sizeof(HMODULE);

	// Get the processes name from the first module returned by the above
	GetModuleBaseName(hProcess, hModule[0], cProcess, MAX_PATH);
	Procs[NumOfProcs].PID = dwPID;
	_tcscpy_s(Procs[NumOfProcs].Name, MAX_PATH, cProcess);
	//fwprintf(stdout, _TEXT("[i] [%d][%s] analyzing\n"), dwPID, cProcess);
	NumOfProcs++;

	//
	// Get the 
	//

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {			
				if (te.th32OwnerProcessID == dwPID && GetProcessId(NULL) != dwPID) {
					HANDLE hThread = INVALID_HANDLE_VALUE;
					hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
					if (hThread != INVALID_HANDLE_VALUE) {
						CONTEXT threadContext = { 0 };
						threadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

						if (GetThreadContext(hThread, &threadContext) == TRUE) {
							//fwprintf(stdout, _TEXT("[i] [%d][%s] analyzing %d %08x %llx\n"), dwPID, cProcess,te.th32ThreadID, threadContext.ContextFlags, threadContext.Dr0);
							
							if (threadContext.Dr0 || threadContext.Dr1 || threadContext.Dr2 || threadContext.Dr3) {
								fwprintf(stdout, _TEXT("[i] [%d][%s] has a thread (%d) with debug registers set - %llx %llx %llx %llx\n"), dwPID, cProcess, te.th32ThreadID, threadContext.Dr0, threadContext.Dr1, threadContext.Dr2, threadContext.Dr3);
							}

							//ResumeThread(hThread);

						}
						CloseHandle(hThread);
					}
				}

			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}


	// fwprintf(stdout, _TEXT("[d] [%d][%s] # of VEH: %d\n"), dwPID, cProcess, dwVEHs);

	dwCountOK++;
	CloseHandle(hProcess);
}

/// <summary>
/// Enumerate all the processes on the system and
/// pass off to the analysis function
/// </summary>
void EnumerateProcesses()
{
	DWORD dwPIDArray[4096], dwRet, dwPIDS, intCount;
	NumOfProcs = 0;

	// Privs
	SetPrivilege(GetCurrentProcess(), SE_DEBUG_NAME);

	// Be clean
	memset(Procs, 0x00, sizeof(Procs));

	//
	// Enumerate
	//
	if (EnumProcesses(dwPIDArray, 4096 * sizeof(DWORD), &dwRet) == 0)
	{
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0) {
			_ftprintf(stderr, TEXT("[!] EnumProcesses() failed - %s"), strErrMsg);
		}
		else
		{
			_ftprintf(stderr, TEXT("[!] EnumProcesses() - Error: %d\n"), GetLastError());
		}
		return;
	}

	// Total nuber of process IDs
	dwPIDS = dwRet / sizeof(DWORD);

	//
	// Analyze
	//
	for (intCount = 0; intCount < dwPIDS; intCount++)
	{
		//fwprintf(stdout, _TEXT("[i] Analyzing PID %d\n"), dwPIDArray[intCount]);
		AnalyzeProc(dwPIDArray[intCount]);
	}

	fwprintf(stdout, _TEXT("[i] Total of %d processes - didn't open %d \n"), dwPIDS, dwOpen);
}