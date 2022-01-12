/*
A copy on write detector for Windows APIs across processes

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/DetectWindowsCopyOnWriteForAPI

Released under AGPL see LICENSE for more information
*/

// Includes
#include "stdafx.h"
#include "XGetopt.h"

// Globals
TCHAR	strErrMsg[1024];
DWORD	dwModuleRelocs = 0; 
void*	eventWrite = GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite");
DWORD	dwCountError = 0;
DWORD	dwCountOK = 0;

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
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684139(v=vs.85).aspx
//
BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			return false;
		}
	}
	return bIsWow64;
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

				DWORD dwBuffSize = MAX_PATH;
				if (QueryFullProcessImageName(hProcess, 0, cProcess, &dwBuffSize) == TRUE) {
					//fwprintf(stderr, _TEXT("[!] [%d][%s] Failed to OpenProcess - %d\n"), dwPID,cProcess, GetLastError());
					dwCountError++;
					return;
				}
				else {
					//fwprintf(stderr, _TEXT("[!] [%d][UNKNOWN] Failed to OpenProcess - %d\n"), dwPID, GetLastError());
					dwCountError++;
					return;
				}
			}
		}
		else {
			//fwprintf(stderr, _TEXT("[!] [%d][UNKNOWN] Failed to OpenProcess - %d\n"), dwPID, GetLastError());
			dwCountError++;
			return;
		}
	}


	// Enumerate the process modules
	if (EnumProcessModules(hProcess, hModule, 4096 * sizeof(HMODULE), &dwRet) == FALSE)
	{
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
	NumOfProcs++;


	// Print the process name
	//fwprintf(stdout, _TEXT("[i]  --> %s\n"), cProcess);


	// Now for each of the modules check that NTDLL is present
	DWORD dwCnt = 0;
	for (dwCnt = 1; dwCnt < dwMods; dwCnt++) {
		
		TCHAR cModule[MAX_PATH]; // Process name
		GetModuleBaseName(hProcess, hModule[dwCnt], cModule, MAX_PATH);


		// Found the module we care about
		if (_tcsicmp(cModule, _TEXT("ntdll.dll")) == 0) {
			// fwprintf(stdout, _TEXT("[i]  ----> Found %s\n"), cModule);

			MODULEINFO modNFO;

			if (GetModuleInformation(hProcess, hModule[dwCnt], &modNFO, sizeof(modNFO)) == TRUE) {
				// fwprintf(stdout, _TEXT("[i]  ----> %p\n"), modNFO.lpBaseOfDll);

				PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)modNFO.lpBaseOfDll;
				PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)modNFO.lpBaseOfDll + DosHeader->e_lfanew);

				for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
					PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(NtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

					// Found the section we care about
					if (!strcmp((char*)SectionHeader->Name, (char*)".text")) {

						// Calculate the address
						// DWORD64 dwAddress = (DWORD64)modNFO.lpBaseOfDll + SectionHeader->VirtualAddress;


						// We are using the address we have resolved in our local process
						// this is fragile and will need fixing
						DWORD64 dwAddress = (DWORD64)eventWrite;

						// fwprintf(stdout, _TEXT("[i]  ----> .text section at %p\n"), dwAddress);
						DWORD dwSize = SectionHeader->Misc.VirtualSize;

						/*
						MEMORY_BASIC_INFORMATION mbNFO;
						if (VirtualQuery((LPCVOID)dwAddress, &mbNFO, sizeof(MEMORY_BASIC_INFORMATION)) == TRUE) {
							if (mbNFO.Protect != MEM_IMAGE) {
								fwprintf(stdout, _TEXT("[i] NTDLL .text section not MEM_IMAGE for %s (%d)\n"), cProcess, dwPID);
							}
						}
						else
						{
							fprintf(stderr, "[!] Error in VirtualQuery(%d),%d\n", dwPID, GetLastError());
						}*/

						// Make sure the function is the expected range						
						if (dwAddress > (DWORD64)modNFO.lpBaseOfDll && dwAddress < ((DWORD64)modNFO.lpBaseOfDll + dwSize)) {

							// Query the working set
							PSAPI_WORKING_SET_EX_INFORMATION info;
							info.VirtualAddress = (LPVOID)dwAddress;

							//fwprintf(stdout, _TEXT("[i] [%d][%s] text section from %p - %p of %d bytes \n"), dwPID, cProcess, info.VirtualAddress, (dwAddress + dwSize), dwSize);
							
							if (QueryWorkingSetEx(hProcess, &info, sizeof(info)) == TRUE) {

								//fwprintf(stdout, _TEXT("[i] [%d][%s] %x)\n"), dwPID, cProcess,info.VirtualAttributes);
								if (info.VirtualAttributes.Shared == 0) fwprintf(stdout, _TEXT("[i] [%d][%s] EtwEventWrite is located in NONE shared memory - indication of copy of write\n"), dwPID, cProcess);
							}
							else
							{
								fprintf(stderr, "[!] Error in QueryWorkingSetEx(%d),%d\n", dwPID, GetLastError());
								dwCountError++;
								return;
							}
						}
					
					}
				}

			}
			else
			{
				fprintf(stderr, "Error in GetModuleInformation(%d),%d\n", dwPID, GetLastError());
				dwCountError++;
				return;
			}

		}
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
	// Test case
	// Remote process patch
	// 
	//DWORD oldOldProt;
	//DWORD oldProt;
	//HANDLE hProcPatch = INVALID_HANDLE_VALUE;
	//hProcPatch = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 11960);
	//VirtualProtectEx(hProcPatch, eventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProt);
	//WriteProcessMemory(hProcPatch, eventWrite, "\xff\xff\xff\xff", 4, NULL);
	//VirtualProtectEx(hProcPatch, eventWrite, 4, oldProt, &oldOldProt);
	//

	//
	// Analyze
	//
	for (intCount = 0; intCount < dwPIDS; intCount++)
	{
		//fwprintf(stdout, _TEXT("[i] Analyzing PID %d\n"), dwPIDArray[intCount]);
		AnalyzeProc(dwPIDArray[intCount]);
	}

	fwprintf(stdout, _TEXT("[i] Total of %d processes %d didn't open  \n"), dwPIDS, dwCountError);

}