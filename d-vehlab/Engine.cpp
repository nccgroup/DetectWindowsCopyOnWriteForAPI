/*
VEH using process enumerator for Microsoft Windows

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/

// Sources
// https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html
// https://www.unknowncheats.me/forum/c-and-c-/160827-internals-addvectoredexceptionhandler.html
// http://rinseandrepeatanalysis.blogspot.com/p/peb-structure.html
// https://bytepointer.com/resources/tebpeb32.htm
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/crossprocessflags.htm
// https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h
// https://github.com/cradiator/CrMisc/blob/master/VEH/VEH/VEH.cpp
// https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/ManualMap/MExcept.cpp

// Includes
#include "stdafx.h"
#include "InternalStructs.h"

// Globals
TCHAR	strErrMsg[1024];
DWORD	dwModuleRelocs = 0;
void* eventWrite = GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite");
DWORD	dwCountError = 0;
DWORD	dwCountOK = 0;
DWORD	dwVEH = 0;
DWORD	dwVCH = 0;

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

template<class T>
static T ror(T x, unsigned int moves)
{
	return (x >> moves) | (x << (sizeof(T) * 8 - moves));
}

template<class T>
static T rol(T x, unsigned int moves)
{
	return (x << moves) | (x >> (sizeof(T) * 8 - moves));
}

// https://github.com/x64dbg/x64dbg/blob/4ee4a51e43cc5d1d11316098e925676046f28a86/src/dbg/memory.cpp
bool MemDecodePointer(unsigned long* Pointer, ULONG cookie)
{

	* Pointer = ror(*Pointer, (0x40 - (cookie & 0x3F)) & 0xFF);

	// XOR pointer with key
	* Pointer ^= cookie;

	return true;
}


BOOL GetVEHfromProc(HANDLE hProcess, ULONGLONG VEHAddress, TCHAR *cProcess, DWORD dwPID, ULONG Cookie) {

	VECTORED_HANDLER_LIST_OW handler_list;

	SIZE_T dwRead = 0;
	if (ReadProcessMemory(hProcess, (LPCVOID)VEHAddress, &handler_list, sizeof(handler_list), &dwRead) == FALSE) {
		return 0;
	}

	
	
	fwprintf(stdout, _TEXT("[d] [%d][%s] VEH end:             0x%.16llX\n"), dwPID, cProcess, VEHAddress + sizeof(DWORD64));
	fwprintf(stdout, _TEXT("[d] [%d][%s] First VEH entry:     0x%p\n"), dwPID,cProcess, handler_list.first_exception_handler);
	fwprintf(stdout, _TEXT("[d] [%d][%s] Last VEH entry:      0x%p\n"), dwPID, cProcess, handler_list.last_exception_handler);

	if ((DWORD64)handler_list.first_exception_handler == VEHAddress + sizeof(DWORD64)) {
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH list is empty\n"), dwPID, cProcess);
		return 0;
	}

	VEH_HANDLER_ENTRY entry;

	// fprintf(stdout, "Reading %p for %zu bytes - %zu %zu %zu %zu\n", (LPCVOID)handler_list.first_exception_handler,sizeof(entry),sizeof(LIST_ENTRY),sizeof(DWORD),sizeof(PVECTORED_EXCEPTION_HANDLER),(sizeof(entry), sizeof(LIST_ENTRY)+ sizeof(DWORD)+ sizeof(PVECTORED_EXCEPTION_HANDLER)));

	if (ReadProcessMemory(hProcess, (LPCVOID)handler_list.first_exception_handler, &entry, sizeof(entry), &dwRead) == FALSE) {
		fprintf(stdout, "Failed to read\n");
		return 0;
	}

	if (dwRead != sizeof(entry)) {
		fprintf(stdout, "Failed to read 2\n");
		return 0;
	}

	void *VectorHandler;
	if (ReadProcessMemory(hProcess, (LPCVOID)(handler_list.first_exception_handler+20), &VectorHandler, 8, &dwRead) == FALSE) {
		fprintf(stdout, "Failed to read\n");
		return 0;
	}


	while (true) {

		// Decode the pointer using the cookie we previously got
		//fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler.count    %u\n"), dwPID, cProcess, entry.Count);
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler.next     0x%p\n"), dwPID, cProcess, (void *)entry.Entry.Flink);
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler.previous 0x%p\n"), dwPID, cProcess, (void*)entry.Entry.Blink);
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler.handler  0x%p\n"), dwPID, cProcess, (void*)entry.VectoredHandler);
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler.handler  0x%p\n"), dwPID, cProcess, (void*)VectorHandler);

		unsigned long dwPtr = (unsigned long)entry.VectoredHandler;
		MemDecodePointer(&dwPtr, Cookie);
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler(decoded) 0x%p\n"), dwPID, cProcess, dwPtr);

		dwPtr = (unsigned long)VectorHandler;
		MemDecodePointer(&dwPtr, Cookie);
		fwprintf(stdout, _TEXT("[d] [%d][%s] VEH handler(decoded)20x%p\n"), dwPID, cProcess, dwPtr);



		if ((DWORD64)(entry.Entry.Flink) == VEHAddress  + sizeof(DWORD64)) {
			break;
		}

		if (ReadProcessMemory(hProcess, (LPCVOID)entry.Entry.Flink, &entry, sizeof(entry), &dwRead) == FALSE) {
			return 0;
		}

		if (ReadProcessMemory(hProcess, (LPCVOID)(handler_list.first_exception_handler + 20), &VectorHandler, 8, &dwRead) == FALSE) {
			fprintf(stdout, "Failed to read\n");
			return 0;
		}

	}

	return TRUE;
}

ULONGLONG GetVEHOffset() {
	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	ULONGLONG procAddress = (ULONGLONG) GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler");
	BYTE* Buffer= (BYTE*)(GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler"));

	fwprintf(stdout, _TEXT("[i] RtlRemoveVectoredExceptionHandler [%llx]\n"), (procAddress));
	

	DWORD dwCount = 0;
	DWORD dwOffset = 0;
	for (dwCount = 0; dwCount < 60; dwCount++) {

		if ((*(Buffer + dwCount) == 0x4c) && (*(Buffer + dwCount + 1) == 0x8d) && (*(Buffer + dwCount +2) == 0x25)) {
			memcpy(&dwOffset, (Buffer + dwCount + 3), 4);
			break;
		}
	}

	// ptr return by GetProcAddress + the seek until our pattern + the instruction to load the RVA
	fwprintf(stdout, _TEXT("[i] LdrpVectorHandlerList [%llx]\n"), ((LONGLONG)Buffer+dwCount+7+dwOffset));

	return ((LONGLONG)Buffer + dwCount + 7 + dwOffset);
}

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


DWORD GetPEB(HANDLE hProcess, PEB *outPEB, DWORD64 *CrossProcessFlags) {
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION ProcessInformation;

	Status = __NtQueryInformationProcess(hProcess, ProcessBasicInformation, (DWORD_PTR *)&ProcessInformation, sizeof(ProcessInformation), NULL);
	if (Status != 0)
	{
		return 0;
	}
	
	SIZE_T dwRead =0;
	if (ReadProcessMemory(hProcess, ProcessInformation.PebBaseAddress, outPEB, sizeof(PEB), &dwRead) == FALSE) {
		return 0;
	}

	PPEB pPEB = (PPEB)ProcessInformation.PebBaseAddress;
	if (ReadProcessMemory(hProcess, (PBYTE)pPEB + 0x50, (LPVOID)CrossProcessFlags, sizeof(DWORD64), &dwRead) == FALSE) {
		return 0;
	}

	return (DWORD)dwRead;
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
		if (QueryFullProcessImageName(hProcess, 0, cProcess, &dwSz ) == TRUE) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] not analysed %d\n"), dwPID, cProcess, GetLastError());
		}
		else {
			fwprintf(stdout, _TEXT("[i] [%d][%s] not analysed %d\n"), dwPID, _TEXT("UNKNOWN"), GetLastError());
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

	
	PEB myPEB;
	DWORD64 CrossProcessFlags = -1;
	if (GetPEB(hProcess, &myPEB, &CrossProcessFlags) > 0) {

		if (myPEB.BeingDebugged == 1) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] is being debugged\n"), dwPID, cProcess);
		}

		if (CrossProcessFlags & 0x4) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] is using VEH - Vectored Exception Handler\n"), dwPID, cProcess);

			dwVEH++;
		}

		if (CrossProcessFlags & 0x8) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] is using VCH - Vectored Continue Handler\n"), dwPID, cProcess);
			dwVCH++;
		}

		if (CrossProcessFlags & 0x80) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] is hot patched\n"), dwPID, cProcess);
		}

		if ((CrossProcessFlags & 0x4) or (CrossProcessFlags & 0x8)) {
			fwprintf(stdout, _TEXT("[i] [%d][%s] process cookie 0x%lx\n"), dwPID, cProcess,GetProcessCookie(hProcess));
			fwprintf(stdout, _TEXT("[i] [%d][%s] process cookie %u\n"), dwPID, cProcess, GetProcessCookie(hProcess));
			
			ULONGLONG dwVEHAddress = GetVEHOffset();
			fwprintf(stdout, _TEXT("[i] [%d][%s] VEH address:         0x%p\n"), dwPID, cProcess, (void*)dwVEHAddress);

			//GetVEHfromProc(hProcess, dwVEHAddress,cProcess, dwPID, GetProcessCookie(hProcess));

		}

		
	}
	else {
		fwprintf(stderr, _TEXT("[!] [%d][UNKNOWN] Failed to get PEB\n"), dwPID);
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

	GetVEHOffset();

	return;

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


	fwprintf(stdout, _TEXT("[i] Total of %d processes %d use VEH and %d use VCH \n"), dwPIDS,dwVEH,dwVCH);

}