/*
TEB Detect Impersonating Threads for Microsoft Windows

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

// Manual import
typedef NTSTATUS(WINAPI* NTQUERYINFOMATIONTHREAD)(HANDLE, LONG, PVOID, ULONG, PULONG);
NTQUERYINFOMATIONTHREAD myNtQueryInformationThread = (NTQUERYINFOMATIONTHREAD)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationThread");

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

void AnalyzeTEB(HANDLE hProcess, HANDLE hThread, DWORD dwPID, TCHAR *cProcess, LPCVOID ptrTEB) {

	MYTEB myTEB;
	SIZE_T szRead=0;

	memset(&myTEB, 0x00, sizeof(myTEB));

	if (ReadProcessMemory(hProcess, ptrTEB, &myTEB, sizeof(myTEB), &szRead) == TRUE) {

		if(szRead != sizeof(myTEB)) fwprintf(stdout, _TEXT("[i] [%d][%s] Size Delta\n"), dwPID, cProcess);

		// fwprintf(stdout, _TEXT("[i] [%d][%s] Got TEB %llx\n"), dwPID, cProcess, ptrTEB);

		//if(myTEB.InitialThread>0)fwprintf(stdout, _TEXT("[i] [%d][%s] Initial thread: %d\n"), dwPID, cProcess, myTEB.InitialThread);

		if (myTEB.CountOfOwnedCriticalSections >0) fwprintf(stdout, _TEXT("[i] [%d][%s] Count of Owned Critical Sections: %d\n"), dwPID, cProcess, myTEB.CountOfOwnedCriticalSections);

		if(myTEB.IsImpersonating > 0 ) fwprintf(stdout, _TEXT("[i] [%d][%s] is impersonating\n"), dwPID, cProcess);

		if(myTEB.RtlExceptionAttached == 1) fwprintf(stdout, _TEXT("[i] [%d][%s] cloned\n"), dwPID, cProcess);
		/*
		//fwprintf(stdout, _TEXT("[i] [%d][%s] %llx %llx - Size %d\n"), dwPID, cProcess,myTEB.NtTib.StackBase, myTEB.NtTib.StackLimit, ((LONGLONG)myTEB.NtTib.StackBase- (LONGLONG)myTEB.NtTib.StackLimit));
		LONGLONG dwSSize = (LONGLONG)myTEB.NtTib.StackBase - (LONGLONG)myTEB.NtTib.StackLimit;
		FLOAT dwFoo = dwSSize / 1024;

		DWORD dwStackSize = (unsigned int)(unsigned short)__rdtsc() + 1021 & 0xfffff000;
		FLOAT dwFoo2 = dwStackSize / 1024;

		if (dwFoo != 8.0 && dwFoo != 16.0 && dwFoo != 32.0 && dwFoo != 64.000000) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] -- %d - %f\n"), dwPID, cProcess, dwSSize, dwFoo);
		}
		
		//fwprintf(stdout, _TEXT("[i] [%d][%s] -- %d - %f\n"), dwPID, _TEXT("SAMPLE"), dwStackSize,dwFoo2);

		if (dwSSize < 1000) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] Alert\n"), dwPID, cProcess);
		}
		*/
		
	}

	
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
					hThread = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
					if (hThread != INVALID_HANDLE_VALUE) {
						
						THREAD_BASIC_INFORMATION threadTBI;

						NTSTATUS statRes = myNtQueryInformationThread(hThread, (THREADINFOCLASS)(0), &threadTBI, sizeof(threadTBI), NULL);
						if (statRes == 0) {
							//fwprintf(stdout, _TEXT("[i] [%d][%s] Address of TEB %llx\n"), dwPID, cProcess, threadTBI.TebBaseAddress);
							AnalyzeTEB(hProcess, hThread, dwPID,cProcess,threadTBI.TebBaseAddress);
						}
						else 
						{
							fwprintf(stdout, _TEXT("[!] [%d][%s] Failed to get TBI %d\n"), dwPID, cProcess,(DWORD)statRes);
						}

						/*
						PVOID startAddress = 0;
						statRes = myNtQueryInformationThread(hThread, (THREADINFOCLASS)(9), &startAddress, sizeof(startAddress), NULL);
						if (statRes == 0) {
							fwprintf(stdout, _TEXT("[i] [%d][%s] Start Address of Thread %llx\n"), dwPID, cProcess, startAddress);
						}
						*/

						CloseHandle(hThread);
					}
				}

			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}

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