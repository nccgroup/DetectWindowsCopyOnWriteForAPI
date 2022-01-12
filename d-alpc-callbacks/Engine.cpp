/*
Enmumerate ALPC call backs

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/


//
// https://github.com/odzhan/injection/tree/master/alpc
// https://modexp.wordpress.com/2019/03/07/process-injection-print-spooler/
// https://rayanfam.com/topics/reversing-windows-internals-part1/
// https://github.com/sbousseaden/injection-1/blob/master/alpc/alpc.cpp
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
typedef NTSTATUS(WINAPI* PFN_NTQUERYSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,OUT PVOID SystemInformation,IN ULONG SystemInformationLength,OUT PULONG ReturnLength OPTIONAL	);
PFN_NTQUERYSYSTEMINFORMATION __NtQuerySystemInformation = (PFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtQuerySystemInformation");

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

#define SystemHandleInformationSize 4096 * 1024 * 2

// https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/get-all-open-handles-and-kernel-object-address-from-userland
// https://github.com/odzhan/injection/blob/master/alpc/alpc.cpp
// https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf - ALPC changed from 45 to 46
DWORD ProcHasALPC(DWORD dwPID) {

	ULONG   ulSize=0;
	DWORD	dwCount = 0;
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);

	__NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, handleTableInformation, SystemHandleInformationSize, &ulSize);

	//fwprintf(stdout, _TEXT("[i] [%d] Got %lu versus max of %lu \n"), dwPID, ulSize, SystemHandleInformationSize);

	for (ULONG dwLoop = 0; dwLoop < handleTableInformation->NumberOfHandles; dwLoop++) {

		SYSTEM_HANDLE handleInfo = (SYSTEM_HANDLE)handleTableInformation->Handles[dwLoop];

		if (handleInfo.ProcessId == dwPID) {
			//fwprintf(stdout, _TEXT("[i] [%d] Found handle for PID %02x\n"), dwPID, handleInfo.ObjectTypeNumber);
			if (handleInfo.ObjectTypeNumber == 46) {
				//fwprintf(stdout, _TEXT("[i] [%d] Has ALPC Ports\n"),dwPID);
				dwCount++;
			}
		}
	}

	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformation);
	return dwCount;
}

BOOL IsValidTCO(HANDLE hProcess, PTP_CALLBACK_OBJECT tco) {
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T                   res;

	// if it's a callback, these values shouldn't be empty  
	if (tco->CleanupGroupMember == NULL ||
		tco->Pool == NULL ||
		tco->CallerAddress.Function == NULL ||
		tco->Callback.Function == NULL) return FALSE;

	// the CleanupGroupMember should reside in read-only
	// area of image
	res = VirtualQueryEx(hProcess,
		(LPVOID)tco->CleanupGroupMember, &mbi, sizeof(mbi));

	if (res != sizeof(mbi)) return FALSE;
	if (!(mbi.Protect & PAGE_READONLY)) return FALSE;
	if (!(mbi.Type & MEM_IMAGE)) return FALSE;

	// the pool object should reside in read+write memory
	res = VirtualQueryEx(hProcess,
		(LPVOID)tco->Pool, &mbi, sizeof(mbi));

	if (res != sizeof(mbi)) return FALSE;
	if (!(mbi.Protect & PAGE_READWRITE)) return FALSE;

	// the caller function should reside in read+executable memory
	res = VirtualQueryEx(hProcess,
		(LPCVOID)tco->CallerAddress.Function, &mbi, sizeof(mbi));

	if (res != sizeof(mbi)) return FALSE;
	if (!(mbi.Protect & PAGE_EXECUTE_READ)) return FALSE;

	// the callback function should reside in read+executable memory
	res = VirtualQueryEx(hProcess,
		(LPCVOID)tco->Callback.Function, &mbi, sizeof(mbi));

	if (res != sizeof(mbi)) return FALSE;
	return (mbi.Protect & PAGE_EXECUTE_READ);
}


BOOL ALPCDiscover(HANDLE hProcess, LPVOID BaseAddress, SIZE_T RegionSize)
{
	LPBYTE               addr = (LPBYTE)BaseAddress;
	SIZE_T               pos;
	BOOL                 bRead, bFound, bInject = FALSE;
	SIZE_T               rd;
	TP_CALLBACK_OBJECT tco;
	TCHAR                filename[MAX_PATH];

	// scan memory for TCO
	for (pos = 0; pos < RegionSize;
		pos += (bFound ? sizeof(TP_CALLBACK_OBJECT) : sizeof(ULONG_PTR)))
	{
		bFound = FALSE;
		// try read TCO from writeable memory
		bRead = ReadProcessMemory(hProcess,	&addr[pos], &tco, sizeof(TP_CALLBACK_OBJECT), &rd);

		// if not read, continue
		if (!bRead) continue;
		// if not size of callback environ, continue
		if (rd != sizeof(TP_CALLBACK_OBJECT)) continue;

		// is this a valid TCO?
		bFound = IsValidTCO(hProcess, &tco);
		if (bFound) {
			// obtain module name where callback resides
			GetMappedFileName(hProcess, (LPVOID)tco.Callback.Function, filename, MAX_PATH*sizeof(TCHAR));

			//fwprintf(stdout, _TEXT("[i] Found Possible\n"));

			// filter by RPCRT4.dll
			if (_tcsstr(_tolower(filename), TEXT("rpcrt4.dll")) != NULL) {
				fwprintf(stdout, _TEXT("[i] Found ALPC port - callback point to %p\n"), filename,tco.Callback.Function);
			}
			else {
				//fwprintf(stdout, _TEXT("[i] Didn't find actual %s\n"), filename);
			}
		}
	}
	
	return bInject;
}

//
// Hunt for ALPC Call Back
//
BOOL HuntALPC(HANDLE hProcess, TCHAR *cProcess, DWORD dwPID) {

	DWORD dwCount = 0;
	SYSTEM_INFO              si;
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T                   res;
	LPBYTE                   addr;     // current address
	
	dwCount = ProcHasALPC(dwPID);

	if (dwCount > 0) {
		fwprintf(stdout, _TEXT("[i] [%d][%s] Has ALPC Ports\n"), dwPID, cProcess);

		// get memory info
		GetSystemInfo(&si);

		// Scan virtual memory for this process upto maximum address available    
		for (addr = 0; addr < (LPBYTE)si.lpMaximumApplicationAddress;)
		{
			res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

			// we only want to scan the heap, 
			// but this will scan stack space too.
			// need to fix that..
			if ((mbi.State == MEM_COMMIT) &&
				(mbi.Type == MEM_PRIVATE) &&
				(mbi.Protect == PAGE_READWRITE))
			{
				ALPCDiscover(hProcess, mbi.BaseAddress, mbi.RegionSize);
			}
			// update address to query
			addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
		}

		
	}

	return TRUE;
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
	// Do the work
	//
	HuntALPC(hProcess, cProcess, dwPID);

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
 