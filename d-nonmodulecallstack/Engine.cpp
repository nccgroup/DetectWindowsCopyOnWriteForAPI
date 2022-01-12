/*
Discover non-module call stack functions in threads

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/


//
// Inspired by https://github.com/thefLink/Hunt-Sleeping-Beacons/blob/main/Hunt-Sleeping-Beacons.c
//

// Includes
#include "stdafx.h"


// Globals
HANDLE	hProcess;
TCHAR	strErrMsg[1024];
DWORD	dwModuleRelocs = 0;
DWORD	dwCountError = 0;
DWORD	dwCountOK = 0;
DWORD	dwThreads = 0;
DWORD	dwUnknown = 0;
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

// Manual imports
_NtQueryInformationProcess __NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
_MyNtQueryInformationProcess __MyNtQueryInformationProcess = (_MyNtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process = fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");


#pragma comment(lib, "DbgHelp.lib") 

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


//
// GetModuleNameFromAddress
BOOL GetModuleNameFromAddress(HANDLE hProcess, PVOID pvPoint, TCHAR* modName) {

	DWORD dwRet, dwMods;
	HMODULE hModule[4096];

	// Enumerate the process modules
	if (EnumProcessModules(hProcess, hModule, 4096 * sizeof(HMODULE), &dwRet) == FALSE)
	{
		fprintf(stderr, "Couldn't enum modules\n");
		return FALSE;
	}
	dwMods = dwRet / sizeof(HMODULE);

	// fwprintf(stdout, _TEXT("[d] VEH handler #1 hunt 0x%p %d\n"), pvPoint,dwMods);

	DWORD dwCnt = 0;
	for (dwCnt = 0; dwCnt < dwMods; dwCnt++) {

		TCHAR cModule[MAX_PATH]; // Process name
		GetModuleBaseName(hProcess, hModule[dwCnt], cModule, MAX_PATH);

		MODULEINFO modNFO;

		if (GetModuleInformation(hProcess, hModule[dwCnt], &modNFO, sizeof(modNFO)) == TRUE) {
			//fwprintf(stdout, _TEXT("[i]  -//-> %p - %d\n"), modNFO.lpBaseOfDll,modNFO.SizeOfImage);

			DWORD64 dwAddress = (DWORD64)pvPoint;

			// Make sure the function is the expected range						
			if (dwAddress > (DWORD64)modNFO.lpBaseOfDll && dwAddress < ((DWORD64)modNFO.lpBaseOfDll + modNFO.SizeOfImage)) {
				//fwprintf(stdout, _TEXT("\n........................\n"));
				_tcscpy_s(modName, MAX_PATH, cModule);
				return TRUE;
			}

		}

	}
	return FALSE;
}

//
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684139(v=vs.85).aspx
//
BOOL IsWow64(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess, &bIsWow64))
		{
			return false;
		}
	}
	return bIsWow64;
}

//
// Decodes encoded pointers
// original: https://github.com/crypt0rr/commando-tools/blob/9216d182fcbc3b3889cf69d1db99469989e8c45e/UACME/Source/Akagi/sup.c
//
PVOID MemDecodePointer(PVOID Pointer, ULONG cookie)
{
	//fprintf(stdout, "%p\n", Pointer);
	return (PVOID)(RotateRight64((ULONG_PTR)Pointer, 0x40 - (cookie & 0x3f)) ^ cookie);

}

//
// Get the Process Cookie to allow the decoding for pointers
//  - the cookies returned have been validated
//
ULONG GetProcessCookie(HANDLE hProcess) {
	NTSTATUS Status;
	ULONG dwProcCookie = 0;

	Status = __MyNtQueryInformationProcess(hProcess, myProcessCookie, (DWORD_PTR*)&dwProcCookie, sizeof(ULONG), NULL);
	if (Status != 0)
	{
		return 0;
	}

	return dwProcCookie;
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
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess == NULL)
	{
		fwprintf(stderr, _TEXT("[!] [%d][UNKNOWN] Failed to OpenProcess - %d\n"), dwPID, GetLastError());
		dwCountError++;
		return;
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

					if (IsWow64(hProcess) == FALSE) {

						hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
						if (hThread != INVALID_HANDLE_VALUE) {
							dwThreads++;

							//
							//
							//
							CONTEXT threadContext = { 0 };

							threadContext.ContextFlags = CONTEXT_CONTROL;

							if (GetThreadContext(hThread, &threadContext) == FALSE) {
								return;
							}

							STACKFRAME64 stackFrame = { 0x00 };
							IMAGEHLP_MODULE64* ptrModinfo = NULL;
							IMAGEHLP_SYMBOL64* ptrSymbol = NULL;
							DWORD64 dwDisplacement = 0;
							char strSymName[1024] = { 0x00 };

							stackFrame.AddrPC.Offset = threadContext.Rip;
							stackFrame.AddrPC.Mode = AddrModeFlat;
							stackFrame.AddrStack.Offset = threadContext.Rsp;
							stackFrame.AddrStack.Mode = AddrModeFlat;
							stackFrame.AddrFrame.Offset = threadContext.Rbp;
							stackFrame.AddrFrame.Mode = AddrModeFlat;

							SymInitialize(hProcess, NULL, TRUE);

							ptrSymbol = (IMAGEHLP_SYMBOL64*)VirtualAlloc(0, sizeof(IMAGEHLP_SYMBOL64) + 1024 * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
							ptrSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64)+1024;
							ptrSymbol->MaxNameLength = 1024;

							ptrModinfo = (IMAGEHLP_MODULE64*)VirtualAlloc(0, sizeof(IMAGEHLP_MODULE64) + 1024 * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
							ptrModinfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64)+1024;

							DWORD dwFrame = 0;
							while (true) {

								if (StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &stackFrame, &threadContext, NULL, &SymFunctionTableAccess64, &SymGetModuleBase64, NULL) == TRUE) {

									SymRefreshModuleList(hProcess);
									SymGetModuleInfo64(hProcess, (ULONG64)stackFrame.AddrPC.Offset, ptrModinfo);
									SymGetSymFromAddr64(hProcess, (ULONG64)stackFrame.AddrPC.Offset, &dwDisplacement, ptrSymbol);
									memset(strSymName, 0x00, 1024);
									UnDecorateSymbolName(ptrSymbol->Name, strSymName, 1024, UNDNAME_COMPLETE);
									fwprintf(stdout, _TEXT("[i] [%d][%d][%s] Frame %d - 0x%p -> %S.%S \n"), dwPID, te.th32ThreadID, cProcess, dwFrame, (void*)threadContext.Rip, ptrModinfo->ImageName, strSymName);
								}
								else {
									fwprintf(stdout, _TEXT("[i] [%d][%d][%s] -----\n"), dwPID, te.th32ThreadID, cProcess);
									break;
								}

								dwFrame++;
							}
							
							CloseHandle(hThread);
						}
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