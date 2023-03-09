#pragma once
#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

typedef struct LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} _LIST_ENTRY, * _PLIST_ENTRY;

typedef struct _PEB_LDR_DATA
{
    _ULONG                  Length;
    _BOOLEAN                Initialized;
    _PVOID                  SsHandle;
    _LIST_ENTRY             InLoadOrderModuleList;
    _LIST_ENTRY             InMemoryOrderModuleList;
    _LIST_ENTRY             InInitializationOrderModuleList;
    _PVOID                  EntryInProgress;
} _PEB_LDR_DATA, * _PPEB_LDR_DATA;

typedef struct _LDR_DATA_ENTRY
{
    _LIST_ENTRY             InLoadOrderModuleList;
    _LIST_ENTRY             InMemoryOrderModuleList;
    _LIST_ENTRY             InInitializationOrderModuleList;
    _PVOID                  BaseAddress;
    _PVOID                  EntryPoint;
    _ULONG                  SizeOfImage;
    _UNICODE_STRING         FullDllName;
    _UNICODE_STRING         BaseDllName;
    _ULONG                  Flags;
    _WORD                   LoadCount;
    _WORD                   TlsIndex;
    _LIST_ENTRY             HashLinks;
    _ULONG                  TimeDateStamp;
    _HANDLE                 ActivationContext;
    _PVOID                  PatchInformation;
    _LIST_ENTRY             ForwarderLinks;
    _LIST_ENTRY             ServiceTagLinks;
    _LIST_ENTRY             StaticLinks;
    _PVOID                  ContextInformation;
    _ULONG_PTR              OriginalBase;
    _LARGE_INTEGER          LoadTime;
} _LDR_DATA_ENTRY, * _PLDR_DATA_ENTRY;//_LDR_MODULE

typedef struct RTL_BITMAP
{
    _ULONG  SizeOfBitMap;
    _PULONG Buffer;
} _RTL_BITMAP, * _PRTL_BITMAP;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
    _USHORT              Flags;
    _USHORT              Length;
    _ULONG               TimeStamp;
    _UNICODE_STRING      DosPath;
} _RTL_DRIVE_LETTER_CURDIR, * _PRTL_DRIVE_LETTER_CURDIR;

typedef struct CURDIR
{
    _UNICODE_STRING     DosPath;
    _PVOID              Handle;
} _CURDIR, * _PCURDIR;

typedef struct RTL_USER_PROCESS_PARAMETERS
{
    _ULONG                      AllocationSize;
    _ULONG                      Size;
    _ULONG                      Flags;
    _ULONG                      DebugFlags;
    _HANDLE                     ConsoleHandle;
    _ULONG                      ConsoleFlags;
    _HANDLE                     hStdInput;
    _HANDLE                     hStdOutput;
    _HANDLE                     hStdError;
    _CURDIR                     CurrentDirectory;
    _UNICODE_STRING             DllPath;
    _UNICODE_STRING             ImagePathName;
    _UNICODE_STRING             CommandLine;
    _PWSTR                      Environment;
    _ULONG                      dwX;
    _ULONG                      dwY;
    _ULONG                      dwXSize;
    _ULONG                      dwYSize;
    _ULONG                      dwXCountChars;
    _ULONG                      dwYCountChars;
    _ULONG                      dwFillAttribute;
    _ULONG                      dwFlags;
    _ULONG                      wShowWindow;
    _UNICODE_STRING             WindowTitle;
    _UNICODE_STRING             Desktop;
    _UNICODE_STRING             ShellInfo;
    _UNICODE_STRING             RuntimeInfo;
    _RTL_DRIVE_LETTER_CURDIR    DLCurrentDirectory[0x20];
} _RTL_USER_PROCESS_PARAMETERS, * _PRTL_USER_PROCESS_PARAMETERS;

typedef struct RTL_CRITICAL_SECTION_DEBUG
{
    _WORD                               Type;
    _WORD                               CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    _LIST_ENTRY                         ProcessLocksList;
    _DWORD                              EntryCount;
    _DWORD                              ContentionCount;
    _DWORD                              Flags;
    _WORD                               CreatorBackTraceIndexHigh;
    _WORD                               Identifier;
} _RTL_CRITICAL_SECTION_DEBUG, * _PRTL_CRITICAL_SECTION_DEBUG, _RTL_RESOURCE_DEBUG, * _PRTL_RESOURCE_DEBUG;

typedef struct RTL_CRITICAL_SECTION
{
    _PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    _LONG LockCount;
    _LONG RecursionCount;
    _HANDLE OwningThread;
    _HANDLE LockSemaphore;
    _ULONG_PTR SpinCount;
} _RTL_CRITICAL_SECTION, * _PRTL_CRITICAL_SECTION;


typedef struct PEB
{                                                                 /* win32/win64 */
    _BOOLEAN                        InheritedAddressSpace;             /* 000/000 */
    _BOOLEAN                        ReadImageFileExecOptions;          /* 001/001 */
    _BOOLEAN                        BeingDebugged;                     /* 002/002 */
    _BOOLEAN                        SpareBool;                         /* 003/003 */
    _HANDLE                         Mutant;                            /* 004/008 */
    _PVOID                          ImageBaseAddress;                  /* 008/010 */
    _PPEB_LDR_DATA                  LdrData;
    _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 /* 010/020 */
    _PVOID                          SubSystemData;                     /* 014/028 */
    _HANDLE                         ProcessHeap;                       /* 018/030 */
    _PRTL_CRITICAL_SECTION          FastPebLock;                       /* 01c/038 */
    _PVOID /*PPEBLOCKROUTINE*/      FastPebLockRoutine;                /* 020/040 */
    _PVOID /*PPEBLOCKROUTINE*/      FastPebUnlockRoutine;              /* 024/048 */
    _ULONG                          EnvironmentUpdateCount;            /* 028/050 */
    _PVOID                          KernelCallbackTable;               /* 02c/058 */
    _ULONG                          Reserved[2];                       /* 030/060 */
    _PVOID /*PPEB_FREE_BLOCK*/      FreeList;                          /* 038/068 */
    _ULONG                          TlsExpansionCounter;               /* 03c/070 */
    _PRTL_BITMAP                    TlsBitmap;                         /* 040/078 */
    _ULONG                          TlsBitmapBits[2];                  /* 044/080 */
    _PVOID                          ReadOnlySharedMemoryBase;          /* 04c/088 */
    _PVOID                          ReadOnlySharedMemoryHeap;          /* 050/090 */
    _PVOID* ReadOnlyStaticServerData;          /* 054/098 */
    _PVOID                          AnsiCodePageData;                  /* 058/0a0 */
    _PVOID                          OemCodePageData;                   /* 05c/0a8 */
    _PVOID                          UnicodeCaseTableData;              /* 060/0b0 */
    _ULONG                          NumberOfProcessors;                /* 064/0b8 */
    _ULONG                          NtGlobalFlag;                      /* 068/0bc */
    _LARGE_INTEGER                  CriticalSectionTimeout;            /* 070/0c0 */
    _ULONG_PTR                      HeapSegmentReserve;                /* 078/0c8 */
    _ULONG_PTR                      HeapSegmentCommit;                 /* 07c/0d0 */
    _ULONG_PTR                      HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
    _ULONG_PTR                      HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
    _ULONG                          NumberOfHeaps;                     /* 088/0e8 */
    _ULONG                          MaximumNumberOfHeaps;              /* 08c/0ec */
    _PVOID* ProcessHeaps;                      /* 090/0f0 */
    _PVOID                          GdiSharedHandleTable;              /* 094/0f8 */
    _PVOID                          ProcessStarterHelper;              /* 098/100 */
    _PVOID                          GdiDCAttributeList;                /* 09c/108 */
    _PVOID                          LoaderLock;                        /* 0a0/110 */
    _ULONG                          OSMajorVersion;                    /* 0a4/118 */
    _ULONG                          OSMinorVersion;                    /* 0a8/11c */
    _ULONG                          OSBuildNumber;                     /* 0ac/120 */
    _ULONG                          OSPlatformId;                      /* 0b0/124 */
    _ULONG                          ImageSubSystem;                    /* 0b4/128 */
    _ULONG                          ImageSubSystemMajorVersion;        /* 0b8/12c */
    _ULONG                          ImageSubSystemMinorVersion;        /* 0bc/130 */
    _ULONG                          ImageProcessAffinityMask;          /* 0c0/134 */
    _HANDLE                         GdiHandleBuffer[28];               /* 0c4/138 */
    _ULONG                          unknown[6];                        /* 134/218 */
    _PVOID                          PostProcessInitRoutine;            /* 14c/230 */
    _PRTL_BITMAP                    TlsExpansionBitmap;                /* 150/238 */
    _ULONG                          TlsExpansionBitmapBits[32];        /* 154/240 */
    _ULONG                          SessionId;                         /* 1d4/2c0 */
    _ULARGE_INTEGER                 AppCompatFlags;                    /* 1d8/2c8 */
    _ULARGE_INTEGER                 AppCompatFlagsUser;                /* 1e0/2d0 */
    _PVOID                          ShimData;                          /* 1e8/2d8 */
    _PVOID                          AppCompatInfo;                     /* 1ec/2e0 */
    _UNICODE_STRING                 CSDVersion;                        /* 1f0/2e8 */
    _PVOID                          ActivationContextData;             /* 1f8/2f8 */
    _PVOID                          ProcessAssemblyStorageMap;         /* 1fc/300 */
    _PVOID                          SystemDefaultActivationData;       /* 200/308 */
    _PVOID                          SystemAssemblyStorageMap;          /* 204/310 */
    _ULONG_PTR                      MinimumStackCommit;                /* 208/318 */
    _PVOID* FlsCallback;                       /* 20c/320 */
    _LIST_ENTRY                     FlsListHead;                       /* 210/328 */
    _PRTL_BITMAP                    FlsBitmap;                         /* 218/338 */
    _ULONG                          FlsBitmapBits[4];                  /* 21c/340 */
} _PEB, * _PPEB;