/*
DLL Load Reason Enumerator for Microsoft Windows

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/

#pragma once

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

//
// Original source: https://github.com/mirror/processhacker/blob/master/2.x/trunk/phlib/include/ntpsapi.h
//
// used for the Process Cookie stuff
//

#pragma once

typedef enum _MYPROCESSINFOCLASS
{
    myProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    myProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    myProcessIoCounters, // q: IO_COUNTERS
    myProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    myProcessTimes, // q: KERNEL_USER_TIMES
    myProcessBasePriority, // s: KPRIORITY
    myProcessRaisePriority, // s: ULONG
    myProcessDebugPort, // q: HANDLE
    myProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    myProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    myProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    myProcessLdtSize, // s: PROCESS_LDT_SIZE
    myProcessDefaultHardErrorMode, // qs: ULONG
    myProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    myProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    myProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    myProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    myProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    myProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    myProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    myProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    myProcessAffinityMask, // s: KAFFINITY
    myProcessPriorityBoost, // qs: ULONG
    myProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    myProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    myProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    myProcessWow64Information, // q: ULONG_PTR
    myProcessImageFileName, // q: UNICODE_STRING
    myProcessLUIDDeviceMapsEnabled, // q: ULONG
    myProcessBreakOnTermination, // qs: ULONG
    myProcessDebugObjectHandle, // q: HANDLE // 30
    myProcessDebugFlags, // qs: ULONG
    myProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    myProcessIoPriority, // qs: IO_PRIORITY_HINT
    myProcessExecuteFlags, // qs: ULONG
    myProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement 
    myProcessCookie, // q: ULONG
    myProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    myProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    myProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    myProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    myProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    myProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    myProcessImageFileNameWin32, // q: UNICODE_STRING
    myProcessImageFileMapping, // q: HANDLE (input)
    myProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    myProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    myProcessGroupInformation, // q: USHORT[]
    myProcessTokenVirtualizationEnabled, // s: ULONG
    myProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    myProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    myProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    myProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    myProcessDynamicFunctionTableInformation,
    myProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    myProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    myProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    myProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    myProcessHandleTable, // q: ULONG[] // since WINBLUE
    myProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    myProcessCommandLineInformation, // q: UNICODE_STRING // 60
    myProcessProtectionInformation, // q: PS_PROTECTION
    myProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    myProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    myProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    myProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    myProcessDefaultCpuSetsInformation,
    myProcessAllowedCpuSetsInformation,
    myProcessSubsystemProcess,
    myProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    myProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    myProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    myProcessIumChallengeResponse,
    myProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    myProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    myProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    myProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    myProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    myProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    myProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    myProcessDisableSystemAllowedCpuSets, // 80
    myProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    myProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    myProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    myProcessCaptureTrustletLiveDump,
    myProcessTelemetryCoverage,
    myProcessEnclaveInformation,
    myProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    myProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    myProcessImageSection, // q: HANDLE
    myProcessDebugAuthInformation, // since REDSTONE4 // 90
    myProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    myProcessSequenceNumber, // q: ULONGLONG
    myProcessLoaderDetour, // since REDSTONE5
    myProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    myProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    myProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    myProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    myProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    myProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    myProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    myProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    myProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    myProcessCreateStateChange, // since WIN11
    myProcessApplyStateChange,
    myProcessEnableOptionalXStateFeatures,
    myMaxProcessInfoClass
} MYPROCESSINFOCLASS;

// Used for ProcessCookie stuff using a different version
// of the ProcessInfoClass
typedef NTSTATUS(WINAPI* _MyNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN MYPROCESSINFOCLASS ProcessInformationClass,
	OUT DWORD_PTR* ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);


//
// https://github.com/mirror/processhacker/blob/master/2.x/trunk/phlib/include/ntldr.h
//

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

#define RTL_BALANCED_NODE_GET_PARENT_POINTER(Node) ((PRTL_BALANCED_NODE)((Node)->ParentValue & ~RTL_BALANCED_NODE_RESERVED_PARENT_MASK))

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG ReferenceCount;
    ULONG DependencyCount;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
    ULONG LowestLink;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef struct my_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG ReservedFlags2 : 1;
            ULONG EntryProcessed : 1;
            ULONG ReservedFlags3 : 3;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_DLL_SNAP_CONTEXT* SnapContext;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
} myLDR_DATA_TABLE_ENTRY, * myPLDR_DATA_TABLE_ENTRY;



// http://downloads.securityfocus.com/vulnerabilities/exploits/26556.c
typedef PIMAGE_NT_HEADERS(NTAPI* RTLIMAGENTHEADER)(DWORD_PTR);




