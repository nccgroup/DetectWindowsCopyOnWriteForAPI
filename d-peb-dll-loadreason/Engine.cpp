/*
DLL Load Reason Enumerator for Microsoft Windows

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/

// Includes
#include "stdafx.h"
#include <time.h>


// Globals
HANDLE	hProcess;
TCHAR	strErrMsg[1024];
DWORD	dwModuleRelocs = 0;
DWORD	dwCountError = 0;
DWORD	dwCountOK = 0;
DWORD	dwVEH = 0;
DWORD	dwVCH = 0;
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
typedef void(__stdcall* pRtlTimeToSecondsSince1970)(PLARGE_INTEGER, PULONG);
pRtlTimeToSecondsSince1970 myRtlTimeToSecondsSince1970 = (pRtlTimeToSecondsSince1970)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "RtlTimeToSecondsSince1970");

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
// Get the PEB for the process we are interested in and then return just the CrossProcessFlags
// 
//
DWORD GetPEB(HANDLE hProcess, PEB* outPEB, DWORD64* CrossProcessFlags) {
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION ProcessInformation;

	Status = __NtQueryInformationProcess(hProcess, ProcessBasicInformation, (DWORD_PTR*)&ProcessInformation, sizeof(ProcessInformation), NULL);
	if (Status != 0)
	{
		return 0;
	}

	SIZE_T dwRead = 0;
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
		if(hProcess!=NULL)CloseHandle(hProcess);
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
		// https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
		// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm?ta=11&tx=205,206,208
		// 
		PEB_LDR_DATA pebLDRData = { 0 };
		LDR_DATA_TABLE_ENTRY pebLDREntry = { 0 };

		// https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block
		// https://www.sysnative.com/forums/threads/finding-dlls-for-a-process-with-windbg.14458/
		// 

		SIZE_T dwRead = 0;
		// myPEB.Ldr
		if (ReadProcessMemory(hProcess, myPEB.Ldr, &pebLDRData, sizeof(myLDR_DATA_TABLE_ENTRY), &dwRead) == TRUE) {

			LIST_ENTRY InMemoryOrderModuleList = (pebLDRData.InMemoryOrderModuleList);
			LIST_ENTRY* headOfList = InMemoryOrderModuleList.Flink;
			myLDR_DATA_TABLE_ENTRY* addressLDREntry = CONTAINING_RECORD(headOfList, myLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			//fwprintf(stdout, _TEXT("[i] [%d][%s] addressLDREntry %p\n"), dwPID, cProcess, addressLDREntry);

			myLDR_DATA_TABLE_ENTRY remoteLDREntry = { 0 };

			BYTE* remoteLDREntryByte = (BYTE *)malloc(sizeof(myLDR_DATA_TABLE_ENTRY));

			if (ReadProcessMemory(hProcess, addressLDREntry, &remoteLDREntry, sizeof(myLDR_DATA_TABLE_ENTRY), &dwRead) == TRUE) {
				
				BOOL bFirstEntry = TRUE;
				DWORD dwFirstSeconds = 0;

				while (TRUE) {
					
					if (remoteLDREntry.DllBase == NULL) break;

					PWSTR strDLL = (PWSTR)malloc(remoteLDREntry.BaseDllName.MaximumLength);

					// get the string's buffer
					if (ReadProcessMemory(hProcess, remoteLDREntry.BaseDllName.Buffer, strDLL, remoteLDREntry.BaseDllName.MaximumLength, &dwRead) == TRUE)
					{
						TCHAR strReason[MAX_PATH];

						// Nasty hack due to https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm?ta=11&tx=205,206,208
						// being accurate and Process Hacker not it would seem
						memcpy(remoteLDREntryByte, &remoteLDREntry, sizeof(myLDR_DATA_TABLE_ENTRY));
						
						DWORD wReason;
						memcpy(&wReason, remoteLDREntryByte + 0x010C, 4);
						
						LARGE_INTEGER loadTime;
						memcpy(&loadTime, remoteLDREntryByte + 0x0100, sizeof(LARGE_INTEGER));
						
						ULONG dwSeconds = 0;
						myRtlTimeToSecondsSince1970(&loadTime, &dwSeconds);

						if (bFirstEntry == TRUE) {
							bFirstEntry = FALSE;
							dwFirstSeconds = dwSeconds;
						}
						time_t timep = (time_t)dwSeconds;
						struct tm tmDest;
						localtime_s(&tmDest ,&timep);

						DWORD dwDelta = dwSeconds - dwFirstSeconds;											

						if (wReason == LoadReasonStaticDependency) {
							_tcscpy_s(strReason, MAX_PATH, _T("Static Dependency"));
						}
						else if (wReason == LoadReasonStaticForwarderDependency) {
							_tcscpy_s(strReason, MAX_PATH, _T("Static Forwarder Dependency"));
						}
						else if (wReason == LoadReasonDynamicForwarderDependency) {
							_tcscpy_s(strReason, MAX_PATH, _T("Dynamic Forwarder Dependency"));
						}
						else if (wReason == LoadReasonDelayloadDependency) {
							_tcscpy_s(strReason, MAX_PATH, _T("Delayload Dependency"));
						}
						else if (wReason == LoadReasonDynamicLoad) {
							_tcscpy_s(strReason, MAX_PATH, _T("Dynamic Load"));
						}
						else if (wReason == LoadReasonAsImageLoad) {
							_tcscpy_s(strReason, MAX_PATH, _T("As Image Load"));
						}
						else if (wReason == LoadReasonAsDataLoad) {
							_tcscpy_s(strReason, MAX_PATH, _T("As Data Load"));
						}
						else {
							_tcscpy_s(strReason, MAX_PATH, _T("Unknown"));
						}

						
						TCHAR strWhen[26];
						wcsftime(strWhen, 26, _TEXT("%Y-%m-%d %H:%M:%S"), &tmDest);
						

						fwprintf(stdout, _TEXT("[i] [%d][%s] Load Reason for %s is %s - loaded @ %s - Delta %d\n"), dwPID, cProcess, strDLL, strReason, strWhen, dwDelta);
						//fwprintf(stdout, _TEXT("[i] [%d][%s] Load Reason for %s is %s - %d\n"), dwPID, cProcess, strDLL, strReason, wReason);

						LIST_ENTRY* nextInList = remoteLDREntry.InMemoryOrderLinks.Flink;
						myLDR_DATA_TABLE_ENTRY* addressNextLDREntry = CONTAINING_RECORD(nextInList, myLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

						// free(remoteLDREntry.FullDllName.Buffer);
						free(strDLL);

						//get the actual remote Table Entry
						if (ReadProcessMemory(hProcess, addressNextLDREntry, &remoteLDREntry, sizeof(myLDR_DATA_TABLE_ENTRY), &dwRead) == FALSE) {
							// Error
							fwprintf(stdout, _TEXT("[i] [%d][%s] Error in ReadProcessMemory - %d\n"), dwPID, cProcess, GetLastError());
							return;
						}

					}
				}

				

				
				
				/*
				while (TRUE) {
				
				}
				*/

			}
			
		}
			
		

		// 
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