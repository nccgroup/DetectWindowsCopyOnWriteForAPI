/*
TEB Detect Impersonating Threads for Microsoft Windows

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


// https://github.com/edouarda/thread_explorer/blob/master/thread_explorer/thread_explorer.cpp
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


// http://daaxr.blogspot.com/2016/07/teb-structure-for-windows-10-pro-x64.html

typedef struct _MYNT_TIB
{
    EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    void* StackBase;
    void* StackLimit;
    void* SubSystemTib;
    union
    {
        void* FiberData;
        unsigned int Version;
    };
    void* ArbitraryUserPointer;
    _MYNT_TIB* Self;
} MYNT_TIB, * PMYNT_TIB;

typedef struct _MYCLIENT_ID
{
    void* UniqueProcess;
    void* UniqueThread;
} MYCLIENT_ID, * PMYCLIENT_ID;

typedef struct _GDI_TEB_BATCH
{
    unsigned __int32 Offset : 31;
    unsigned __int32 HasRenderingCommand : 1;
    unsigned __int64 HDC;
    unsigned int Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef const struct _TEB_ACTIVE_FRAME_CONTEXT
{
    unsigned int Flags;
    const char* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    unsigned int Flags;
    _TEB_ACTIVE_FRAME* Previous;
    _TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;


typedef struct _myTEB
{
    MYNT_TIB NtTib;
    void* EnvironmentPointer;
    CLIENT_ID ClientId;
    void* ActiveRpcHandle;
    void* ThreadLocalStoragePointer;
    PEB* ProcessEnvironmentBlock;
    unsigned int LastErrorValue;
    unsigned int CountOfOwnedCriticalSections;
    void* CsrClientThread;
    void* Win32ThreadInfo;
    unsigned int User32Reserved[26];
    unsigned int UserReserved[5];
    void* WOW32Reserved;
    unsigned int CurrentLocale;
    unsigned int FpSoftwareStatusRegister;
    void* ReservedForDebuggerInstrumentation[16];
    void* SystemReserved1[38];
    int ExceptionCode;
    char Padding0[4];
    __int64* ActivationContextStackPointer;
    unsigned __int64 InstrumentationCallbackSp;
    unsigned __int64 InstrumentationCallbackPreviousPc;
    unsigned __int64 InstrumentationCallbackPreviousSp;
    unsigned int TxFsContext;
    char InstrumentationCallbackDisabled;
    char Padding1[3];
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    void* GdiCachedProcessHandle;
    unsigned int GdiClientPID;
    unsigned int GdiClientTID;
    void* GdiThreadLocalInfo;
    unsigned __int64 Win32ClientInfo[62];
    void* glDispatchTable[233];
    unsigned __int64 glReserved1[29];
    void* glReserved2;
    void* glSectionInfo;
    void* glSection;
    void* glTable;
    void* glCurrentRC;
    void* glContext;
    unsigned int LastStatusValue;
    char Padding2[4];
    UNICODE_STRING StaticUnicodeString;
    wchar_t StaticUnicodeBuffer[261];
    char Padding3[6];
    void* DeallocationStack;
    void* TlsSlots[64];
    LIST_ENTRY TlsLinks;
    void* Vdm;
    void* ReservedForNtRpc;
    void* DbgSsReserved[2];
    unsigned int HardErrorMode;
    char Padding4[4];
    void* Instrumentation[11];
    GUID ActivityId;
    void* SubProcessTag;
    void* PerflibData;
    void* EtwTraceData;
    void* WinSockData;
    unsigned int GdiBatchCount;
    union
    {
        _PROCESSOR_NUMBER CurrentIdealProcessor;
        unsigned int IdealProcessorValue;
        struct DUMMYSTRUCTNAME
        {
            char ReservedPad0;
            char ReservedPad1;
            char ReservedPad2;
            char IdealProcessor;
        };
    };
    unsigned int GuaranteedStackBytes;
    char Padding5[4];
    void* ReservedForPerf;
    void* ReservedForOle;
    unsigned int WaitingOnLoaderLock;
    char Padding6[4];
    void* SavedPriorityState;
    unsigned __int64 ReservedForCodeCoverage;
    void* ThreadPoolData;
    void** TlsExpansionSlots;
    void* DeallocationBStore;
    void* BStoreLimit;
    unsigned int MuiGeneration;
    unsigned int IsImpersonating;
    void* NlsCache;
    void* pShimData;
    unsigned __int16 HeapVirtualAffinity;
    unsigned __int16 LowFragHeapDataSlot;
    char Padding7[4];
    void* CurrentTransactionHandle;
    TEB_ACTIVE_FRAME* ActiveFrame;
    void* FlsData;
    void* PreferredLanguages;
    void* UserPrefLanguages;
    void* MergedPrefLanguages;
    unsigned int MuiImpersonation;
    union
    {
        volatile unsigned __int16 CrossTebFlags;
        struct DUMMYSTRUCTNAME
        {
            unsigned __int16 SpareCrossTebBits : 16;
        };
    };
    union
    {
        unsigned __int16 SameTebFlags;
        struct DUMMYSTRUCTNAME
        {
            unsigned __int16 SafeThunkCall : 1;
            unsigned __int16 InDebugPrint : 1;
            unsigned __int16 HasFiberData : 1;
            unsigned __int16 SkipThreadAttach : 1;
            unsigned __int16 WerInShipAssertCode : 1;
            unsigned __int16 RanProcessInit : 1;
            unsigned __int16 ClonedThread : 1;
            unsigned __int16 SuppressDebugMsg : 1;
            unsigned __int16 DisableUserStackWalk : 1;
            unsigned __int16 RtlExceptionAttached : 1;
            unsigned __int16 InitialThread : 1;
            unsigned __int16 SessionAware : 1;
            unsigned __int16 LoadOwner : 1;
            unsigned __int16 LoaderWorker : 1;
            unsigned __int16 SpareSameTebBits : 2;
        };
    };
    void* TxnScopeEnterCallback;
    void* TxnScopeExitCallback;
    void* TxnScopeContext;
    unsigned int LockCount;
    int WowTebOffset;
    void* ResourceRetValue;
    void* ReservedForWdf;
    unsigned __int64 ReservedForCrt;
    GUID EffectiveContainerId;
} MYTEB, * PMYTEB;


