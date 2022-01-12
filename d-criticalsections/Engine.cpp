/*
Critical Section Enumerator for Windows Processes

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/


//
// https://community.osr.com/discussion/292484/locate-critical-section-location
// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/displaying-a-critical-section
// https://stackoverflow.com/questions/10659578/how-to-get-the-list-of-critical-sections-in-a-process
// https://www.titanwolf.org/Network/q/ccb8f0df-e515-4a51-9c04-1890aa207a2a/y
// https://stackoverflow.com/questions/24330452/critical-section-doesnt-have-debuginfo
//

// Includes
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

// Manual imports
_NtQueryInformationProcess __NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
_MyNtQueryInformationProcess __MyNtQueryInformationProcess = (_MyNtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process = fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
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

//
//
//
ULONGLONG GetRTLCritSecAddress() {
	CRITICAL_SECTION myCrit;
	LONGLONG llSecAddress=0;
	RTL_CRITICAL_SECTION_DEBUG myCritDebug;

	if (InitializeCriticalSectionEx(&myCrit, 1, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO)) {

		//fwprintf(stdout, _TEXT("[i] DebugInfo [%llx]\n"), (LONGLONG)myCrit.DebugInfo);
		
		memcpy(&myCritDebug, myCrit.DebugInfo, sizeof(RTL_CRITICAL_SECTION_DEBUG));

		LIST_ENTRY lstEntry = myCritDebug.ProcessLocksList;

		//fwprintf(stdout, _TEXT("[i] myCrit.DebugInfo->ProcessLocksList.Blink [%llx]\n"), (LONGLONG)lstEntry.Blink);
		//fwprintf(stdout, _TEXT("[i] myCrit.DebugInfo->ProcessLocksList.Flink [%llx]\n"), (LONGLONG)lstEntry.Flink); // this contains the address of RtlCriticalSectionList
		
		memcpy(&llSecAddress,&lstEntry.Flink,sizeof(LONGLONG));

		//fwprintf(stdout, _TEXT("[i] RtlCriticalSectionList [%llx]\n"), (LONGLONG)llSecAddress);
	}
	return llSecAddress;
}


ULONGLONG WalkList(HANDLE hProcess, TCHAR *cProcess, DWORD dwPID, LONGLONG lstHead) {
	
	DWORD dwCritSecs = 0;
	LIST_ENTRY lstEntry;
	LONGLONG llReadAddress = lstHead;
	SIZE_T dwRead = 0;
	BOOL bFirstinList = TRUE;
	LONGLONG llEnd = 0;

	while (true) {

		//fwprintf(stdout, _TEXT("[i] Reading [%llx]\n"), (LONGLONG)llReadAddress);

		if (ReadProcessMemory(hProcess, (LPCVOID)llReadAddress, &lstEntry, sizeof(LIST_ENTRY), &dwRead) == FALSE) {
			return 0;
		}

		if (bFirstinList == TRUE) {
			memcpy(&llEnd, &lstEntry.Blink, sizeof(LONGLONG));
			bFirstinList = FALSE;
		}

		//fwprintf(stdout, _TEXT("[i] lstEntry.Blink [%llx]\n"), (LONGLONG)lstEntry.Blink);
		//fwprintf(stdout, _TEXT("[i] lstEntry.Flink [%llx]\n"), (LONGLONG)lstEntry.Flink);
		dwCritSecs++;

		memcpy(&llReadAddress, &lstEntry.Flink, sizeof(LONGLONG));
		if (llReadAddress == llEnd) break;
	}

	fwprintf(stdout, _TEXT("[i] [%d][%s] has %d Critical Sections\n"), dwPID, cProcess, dwCritSecs);
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


	ULONGLONG dwCritSecListAddress = GetRTLCritSecAddress();
	WalkList(hProcess, cProcess, dwPID, dwCritSecListAddress);
	
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