#pragma once
#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

//-----------------START Windows Defines-----------------//
#ifndef _OPTIONAL
#define _OPTIONAL
#endif

#define _DUMMYUNIONNAME
#define _DUMMYSTRUCTNAME
#define NULL_PTR                                    (void*)0
#define _VOID                                       void
#define _NTAPI                                      __stdcall
#define _WINAPI                                     __stdcall
#define _CBASE                                      __cdecl
#define _APIENTRY                                   WINAPI

#ifndef FALSE
#define FALSE                                       0
#endif

#ifndef TRUE
#define TRUE                                        1
#endif

#define 	_FILE_SUPERSEDE                         0x00000000
#define 	_FILE_OPEN                              0x00000001
#define 	_FILE_CREATE                            0x00000002
#define 	_FILE_OPEN_IF                           0x00000003
#define 	_FILE_OVERWRITE                         0x00000004
#define 	_FILE_MAXIMUM_DISPOSITION               0x00000005
#define 	_FILE_DIRECTORY_FILE                    0x00000001
#define 	_FILE_WRITE_THROUGH                     0x00000002
#define 	_FILE_SEQUENTIAL_ONLY                   0x00000004
#define 	_FILE_NO_INTERMEDIATE_BUFFERING         0x00000008
#define 	_FILE_SYNCHRONOUS_IO_ALERT              0x00000010
#define 	_FILE_SYNCHRONOUS_IO_NONALERT           0x00000020
#define 	_FILE_NON_DIRECTORY_FILE                0x00000040
#define 	_FILE_CREATE_TREE_CONNECTION            0x00000080
#define 	_FILE_COMPLETE_IF_OPLOCKED              0x00000100
#define 	_FILE_NO_EA_KNOWLEDGE                   0x00000200
#define 	_FILE_OPEN_FOR_RECOVERY                 0x00000400
#define 	_FILE_RANDOM_ACCESS                     0x00000800
#define 	_FILE_DELETE_ON_CLOSE                   0x00001000
#define 	_FILE_OPEN_BY_FILE_ID                   0x00002000
#define 	_FILE_OPEN_FOR_BACKUP_INTENT            0x00004000
#define 	_FILE_NO_COMPRESSION                    0x00008000
#define 	_FILE_OPEN_REQUIRING_OPLOCK             0x00010000
#define 	_FILE_DISALLOW_EXCLUSIVE                0x00020000
#define 	_FILE_SESSION_AWARE                     0x00040000
#define 	_FILE_RESERVE_OPFILTER                  0x00100000
#define 	_FILE_OPEN_REPARSE_POINT                0x00200000
#define 	_FILE_OPEN_NO_RECALL                    0x00400000
#define 	_FILE_OPEN_FOR_FREE_SPACE_QUERY         0x00800000
#define 	_FILE_COPY_STRUCTURED_STORAGE           0x00000041
#define 	_FILE_STRUCTURED_STORAGE                0x00000441
#define 	_FILE_SUPERSEDED                        0x00000000
#define 	_FILE_OPENED                            0x00000001
#define 	_FILE_CREATED                           0x00000002
#define 	_FILE_OVERWRITTEN                       0x00000003
#define 	_FILE_EXISTS                            0x00000004
#define 	_FILE_DOES_NOT_EXIST                    0x00000005
#define 	_FILE_WRITE_TO_END_OF_FILE              0xffffffff
#define 	_FILE_USE_FILE_POINTER_POSITION         0xfffffffe

#define _FILE_SHARE_READ                            0x00000001  
#define _FILE_SHARE_WRITE                           0x00000002  
#define _FILE_SHARE_DELETE                          0x00000004  
#define _FILE_ATTRIBUTE_READONLY                    0x00000001  
#define _FILE_ATTRIBUTE_HIDDEN                      0x00000002  
#define _FILE_ATTRIBUTE_SYSTEM                      0x00000004  
#define _FILE_ATTRIBUTE_DIRECTORY                   0x00000010  
#define _FILE_ATTRIBUTE_ARCHIVE                     0x00000020  
#define _FILE_ATTRIBUTE_DEVICE                      0x00000040  
#define _FILE_ATTRIBUTE_NORMAL                      0x00000080  
#define _FILE_ATTRIBUTE_TEMPORARY                   0x00000100  
#define _FILE_ATTRIBUTE_SPARSE_FILE                 0x00000200  
#define _FILE_ATTRIBUTE_REPARSE_POINT               0x00000400  
#define _FILE_ATTRIBUTE_COMPRESSED                  0x00000800  
#define _FILE_ATTRIBUTE_OFFLINE                     0x00001000  
#define _FILE_ATTRIBUTE_NOT_CONTENT_INDEXED         0x00002000  
#define _FILE_ATTRIBUTE_ENCRYPTED                   0x00004000  
#define _FILE_ATTRIBUTE_INTEGRITY_STREAM            0x00008000  
#define _FILE_ATTRIBUTE_VIRTUAL                     0x00010000  
#define _FILE_ATTRIBUTE_NO_SCRUB_DATA               0x00020000  
#define _FILE_ATTRIBUTE_EA                          0x00040000  
#define _FILE_ATTRIBUTE_PINNED                      0x00080000  
#define _FILE_ATTRIBUTE_UNPINNED                    0x00100000  
#define _FILE_ATTRIBUTE_RECALL_ON_OPEN              0x00040000  
#define _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS       0x00400000 

#define 	_OBJ_INHERIT                            0x00000002
#define 	_OBJ_PERMANENT                          0x00000010
#define 	_OBJ_EXCLUSIVE                          0x00000020
#define 	_OBJ_CASE_INSENSITIVE                   0x00000040
#define 	_OBJ_OPENIF                             0x00000080
#define 	_OBJ_OPENLINK                           0x00000100
#define 	_OBJ_KERNEL_HANDLE                      0x00000200
#define 	_OBJ_FORCE_ACCESS_CHECK                 0x00000400
#define 	_OBJ_VALID_ATTRIBUTES                   0x000007f2

#define _IMAGE_FILE_MACHINE_UNKNOWN                 0x0000
#define _IMAGE_FILE_MACHINE_TARGET_HOST             0x0001
#define _IMAGE_FILE_MACHINE_I386                    0x014c// Intel 386.
#define _IMAGE_FILE_MACHINE_R3000                   0x0162
#define _IMAGE_FILE_MACHINE_R4000                   0x0166  
#define _IMAGE_FILE_MACHINE_R10000                  0x0168 
#define _IMAGE_FILE_MACHINE_WCEMIPSV2               0x0169  
#define _IMAGE_FILE_MACHINE_ALPHA                   0x0184  
#define _IMAGE_FILE_MACHINE_SH3                     0x01a2 
#define _IMAGE_FILE_MACHINE_SH3DSP                  0x01a3
#define _IMAGE_FILE_MACHINE_SH3E                    0x01a4
#define _IMAGE_FILE_MACHINE_SH4                     0x01a6
#define _IMAGE_FILE_MACHINE_SH5                     0x01a8
#define _IMAGE_FILE_MACHINE_ARM                     0x01c0
#define _IMAGE_FILE_MACHINE_THUMB                   0x01c2
#define _IMAGE_FILE_MACHINE_ARMNT                   0x01c4
#define _IMAGE_FILE_MACHINE_AM33                    0x01d3
#define _IMAGE_FILE_MACHINE_POWERPC                 0x01F0
#define _IMAGE_FILE_MACHINE_POWERPCFP               0x01f1
#define _IMAGE_FILE_MACHINE_IA64                    0x0200// Intel 64
#define _IMAGE_FILE_MACHINE_MIPS16                  0x0266
#define _IMAGE_FILE_MACHINE_ALPHA64                 0x0284
#define _IMAGE_FILE_MACHINE_MIPSFPU                 0x0366
#define _IMAGE_FILE_MACHINE_MIPSFPU16               0x0466
#define _IMAGE_FILE_MACHINE_AXP64                   _IMAGE_FILE_MACHINE_ALPHA64
#define _IMAGE_FILE_MACHINE_TRICORE                 0x0520
#define _IMAGE_FILE_MACHINE_CEF                     0x0CEF
#define _IMAGE_FILE_MACHINE_EBC                     0x0EBC
#define _IMAGE_FILE_MACHINE_AMD64                   0x8664// AMD64 (K8)
#define _IMAGE_FILE_MACHINE_M32R                    0x9041
#define _IMAGE_FILE_MACHINE_ARM64                   0xAA64
#define _IMAGE_FILE_MACHINE_CEE                     0xC0EE

#define _IMAGE_SUBSYSTEM_UNKNOWN                    0   // Unknown subsystem.
#define _IMAGE_SUBSYSTEM_NATIVE                     1   // Image doesn't require a subsystem.
#define _IMAGE_SUBSYSTEM_WINDOWS_GUI                2   // Image runs in the Windows GUI subsystem.
#define _IMAGE_SUBSYSTEM_WINDOWS_CUI                3   // Image runs in the Windows character subsystem.
#define _IMAGE_SUBSYSTEM_OS2_CUI                    5   // image runs in the OS/2 character subsystem.
#define _IMAGE_SUBSYSTEM_POSIX_CUI                  7   // image runs in the Posix character subsystem.
#define _IMAGE_SUBSYSTEM_NATIVE_WINDOWS             8   // image is a native Win9x driver.
#define _IMAGE_SUBSYSTEM_WINDOWS_CE_GUI             9   // Image runs in the Windows CE subsystem.
#define _IMAGE_SUBSYSTEM_EFI_APPLICATION            10  //
#define _IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    11   //
#define _IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER         12  //
#define _IMAGE_SUBSYSTEM_EFI_ROM                    13
#define _IMAGE_SUBSYSTEM_XBOX                       14
#define _IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION   16
#define _IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG          17

#define _IMAGE_LIBRARY_PROCESS_INIT                             0x0001     // Reserved.
#define _IMAGE_LIBRARY_PROCESS_TERM                             0x0002     // Reserved.
#define _IMAGE_LIBRARY_THREAD_INIT                              0x0004     // Reserved.
#define _IMAGE_LIBRARY_THREAD_TERM                              0x0008     // Reserved.
#define _IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA               0x0020//64-bit  
#define _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE                  0x0040    
#define _IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY               0x0080     
#define _IMAGE_DLLCHARACTERISTICS_NX_COMPAT                     0x0100// DEP
#define _IMAGE_DLLCHARACTERISTICS_NO_ISOLATION                  0x0200     
#define _IMAGE_DLLCHARACTERISTICS_NO_SEH                        0x0400     
#define _IMAGE_DLLCHARACTERISTICS_NO_BIND                       0x0800    
#define _IMAGE_DLLCHARACTERISTICS_APPCONTAINER                  0x1000 
#define _IMAGE_DLLCHARACTERISTICS_WDM_DRIVER                    0x2000   
#define _IMAGE_DLLCHARACTERISTICS_GUARD_CF                      0x4000
#define _IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE         0x8000

#define _IMAGE_FILE_RELOCS_STRIPPED                             0x0001  // Relocation info stripped from file.
#define _IMAGE_FILE_EXECUTABLE_IMAGE                            0x0002  // File is executable  (i.e. no unresolved external references).
#define _IMAGE_FILE_LINE_NUMS_STRIPPED                          0x0004  // Line nunbers stripped from file.
#define _IMAGE_FILE_LOCAL_SYMS_STRIPPED                         0x0008  // Local symbols stripped from file.
#define _IMAGE_FILE_AGGRESIVE_WS_TRIM                           0x0010  // Aggressively trim working set
#define _IMAGE_FILE_LARGE_ADDRESS_AWARE                         0x0020  // App can handle >2gb addresses
#define _IMAGE_FILE_BYTES_REVERSED_LO                           0x0080  // Bytes of machine word are reversed.
#define _IMAGE_FILE_32BIT_MACHINE                               0x0100  // 32 bit word machine.
#define _IMAGE_FILE_DEBUG_STRIPPED                              0x0200  // Debugging info stripped from file in .DBG file
#define _IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP                     0x0400  // If Image is on removable media, copy and run from the swap file.
#define _IMAGE_FILE_NET_RUN_FROM_SWAP                           0x0800  // If Image is on Net, copy and run from the swap file.
#define _IMAGE_FILE_SYSTEM                                      0x1000  // System File.
#define _IMAGE_FILE_DLL                                         0x2000  // File is a DLL.
#define _IMAGE_FILE_UP_SYSTEM_ONLY                              0x4000  // File should only be run on a UP machine
#define _IMAGE_FILE_BYTES_REVERSED_HI                           0x8000  // Bytes of machine word are reversed.

#define _MEM_COMMIT                                             0x00001000  
#define _MEM_RESERVE                                            0x00002000  
#define _MEM_REPLACE_PLACEHOLDER                                0x00004000  
#define _MEM_RESERVE_PLACEHOLDER                                0x00040000  
#define _MEM_RESET                                              0x00080000  
#define _MEM_TOP_DOWN                                           0x00100000  
#define _MEM_WRITE_WATCH                                        0x00200000  
#define _MEM_PHYSICAL                                           0x00400000  
#define _MEM_ROTATE                                             0x00800000  
#define _MEM_DIFFERENT_IMAGE_BASE_OK                            0x00800000  
#define _MEM_RESET_UNDO                                         0x01000000  
#define _MEM_LARGE_PAGES                                        0x20000000  
#define _MEM_4MB_PAGES                                          0x80000000  
#define _MEM_64K_PAGES                                          (MEM_LARGE_PAGES | MEM_PHYSICAL)  
#define _MEM_UNMAP_WITH_TRANSIENT_BOOST                         0x00000001  
#define _MEM_COALESCE_PLACEHOLDERS                              0x00000001  
#define _MEM_PRESERVE_PLACEHOLDER                               0x00000002  
#define _MEM_DECOMMIT                                           0x00004000  
#define _MEM_RELEASE                                            0x00008000  
#define _MEM_FREE                                               0x00010000  

#define _PAGE_NOACCESS                                          0x01    
#define _PAGE_READONLY                                          0x02    
#define _PAGE_READWRITE                                         0x04    
#define _PAGE_WRITECOPY                                         0x08    
#define _PAGE_EXECUTE                                           0x10    
#define _PAGE_EXECUTE_READ                                      0x20    
#define _PAGE_EXECUTE_READWRITE                                 0x40    
#define _PAGE_EXECUTE_WRITECOPY                                 0x80    
#define _PAGE_GUARD                                             0x100    
#define _PAGE_NOCACHE                                           0x200    
#define _PAGE_WRITECOMBINE                                      0x400    
#define _PAGE_GRAPHICS_NOACCESS                                 0x0800    
#define _PAGE_GRAPHICS_READONLY                                 0x1000    
#define _PAGE_GRAPHICS_READWRITE                                0x2000    
#define _PAGE_GRAPHICS_EXECUTE                                  0x4000    
#define _PAGE_GRAPHICS_EXECUTE_READ                             0x8000    
#define _PAGE_GRAPHICS_EXECUTE_READWRITE                        0x10000    
#define _PAGE_GRAPHICS_COHERENT                                 0x20000    
#define _PAGE_GRAPHICS_NOCACHE                                  0x40000    
#define _PAGE_ENCLAVE_THREAD_CONTROL                            0x80000000  
#define _PAGE_REVERT_TO_FILE_MAP                                0x80000000  
#define _PAGE_TARGETS_NO_UPDATE                                 0x40000000  
#define _PAGE_TARGETS_INVALID                                   0x40000000  
#define _PAGE_ENCLAVE_UNVALIDATED                               0x20000000  
#define _PAGE_ENCLAVE_MASK                                      0x10000000  
#define _PAGE_ENCLAVE_DECOMMIT                                  (_PAGE_ENCLAVE_MASK | 0) 
#define _PAGE_ENCLAVE_SS_FIRST                                  (_PAGE_ENCLAVE_MASK | 1) 
#define _PAGE_ENCLAVE_SS_REST                                   (_PAGE_ENCLAVE_MASK | 2) 

#define _DLL_PROCESS_ATTACH                                     0x1    
#define _DLL_THREAD_ATTACH                                      0x2    
#define _DLL_THREAD_DETACH                                      0x3    
#define _DLL_PROCESS_DETACH                                     0x0    

#define _IMAGE_DIRECTORY_ENTRY_EXPORT                           0   // Export Directory
#define _IMAGE_DIRECTORY_ENTRY_IMPORT                           1   // Import Directory
#define _IMAGE_DIRECTORY_ENTRY_RESOURCE                         2   // Resource Directory
#define _IMAGE_DIRECTORY_ENTRY_EXCEPTION                        3   // Exception Directory
#define _IMAGE_DIRECTORY_ENTRY_SECURITY                         4   // Security Directory
#define _IMAGE_DIRECTORY_ENTRY_BASERELOC                        5   // Base Relocation Table
#define _IMAGE_DIRECTORY_ENTRY_DEBUG                            6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define _IMAGE_DIRECTORY_ENTRY_ARCHITECTURE                     7   // Architecture Specific Data
#define _IMAGE_DIRECTORY_ENTRY_GLOBALPTR                        8   // RVA of GP
#define _IMAGE_DIRECTORY_ENTRY_TLS                              9   // TLS Directory
#define _IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG                      10   // Load Configuration Directory
#define _IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT                     11   // Bound Import Directory in headers
#define _IMAGE_DIRECTORY_ENTRY_IAT                              12   // Import Address Table
#define _IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT                     13   // Delay Load Import Descriptors
#define _IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR                   14   // COM Runtime descriptor

#define _IMAGE_REL_BASED_ABSOLUTE                               0
#define _IMAGE_REL_BASED_HIGH                                   1
#define _IMAGE_REL_BASED_LOW                                    2
#define _IMAGE_REL_BASED_HIGHLOW                                3
#define _IMAGE_REL_BASED_HIGHADJ                                4
#define _IMAGE_REL_BASED_MACHINE_SPECIFIC_5                     5
#define _IMAGE_REL_BASED_RESERVED                               6
#define _IMAGE_REL_BASED_MACHINE_SPECIFIC_7                     7
#define _IMAGE_REL_BASED_MACHINE_SPECIFIC_8                     8
#define _IMAGE_REL_BASED_MACHINE_SPECIFIC_9                     9
#define _IMAGE_REL_BASED_DIR64                                  10

#define _IMAGE_SCN_TYPE_REG                                     0x00000000  // Reserved.
#define _IMAGE_SCN_TYPE_DSECT                                   0x00000001  // Reserved.
#define _IMAGE_SCN_TYPE_NOLOAD                                  0x00000002  // Reserved.
#define _IMAGE_SCN_TYPE_GROUP                                   0x00000004  // Reserved.
#define _IMAGE_SCN_TYPE_NO_PAD                                  0x00000008  // Reserved.
#define _IMAGE_SCN_TYPE_COPY                                    0x00000010  // Reserved.

#define _IMAGE_SCN_CNT_CODE                                     0x00000020  
#define _IMAGE_SCN_CNT_INITIALIZED_DATA                         0x00000040  
#define _IMAGE_SCN_CNT_UNINITIALIZED_DATA                       0x00000080 

#define _IMAGE_SCN_LNK_OTHER                                    0x00000100  // Reserved.
#define _IMAGE_SCN_LNK_INFO                                     0x00000200 
#define _IMAGE_SCN_TYPE_OVER                                    0x00000400  // Reserved.
#define _IMAGE_SCN_LNK_REMOVE                                   0x00000800  
#define _IMAGE_SCN_LNK_COMDAT                                   0x00001000  
//                                           0x00002000  // Reserved.
#define _IMAGE_SCN_MEM_PROTECTED                                0x00004000//- Obsolete
#define _IMAGE_SCN_NO_DEFER_SPEC_EXC                            0x00004000  
#define _IMAGE_SCN_GPREL                                        0x00008000  
#define _IMAGE_SCN_MEM_FARDATA                                  0x00008000
#define _IMAGE_SCN_MEM_SYSHEAP                                  0x00010000//- Obsolete
#define _IMAGE_SCN_MEM_PURGEABLE                                0x00020000
#define _IMAGE_SCN_MEM_16BIT                                    0x00020000
#define _IMAGE_SCN_MEM_LOCKED                                   0x00040000
#define _IMAGE_SCN_MEM_PRELOAD                                  0x00080000

#define _IMAGE_SCN_ALIGN_1BYTES                                 0x00100000  
#define _IMAGE_SCN_ALIGN_2BYTES                                 0x00200000  
#define _IMAGE_SCN_ALIGN_4BYTES                                 0x00300000  
#define _IMAGE_SCN_ALIGN_8BYTES                                 0x00400000  
#define _IMAGE_SCN_ALIGN_16BYTES                                0x00500000  
#define _IMAGE_SCN_ALIGN_32BYTES                                0x00600000  
#define _IMAGE_SCN_ALIGN_64BYTES                                0x00700000  
#define _IMAGE_SCN_ALIGN_128BYTES                               0x00800000  
#define _IMAGE_SCN_ALIGN_256BYTES                               0x00900000  
#define _IMAGE_SCN_ALIGN_512BYTES                               0x00A00000  
#define _IMAGE_SCN_ALIGN_1024BYTES                              0x00B00000  
#define _IMAGE_SCN_ALIGN_2048BYTES                              0x00C00000  
#define _IMAGE_SCN_ALIGN_4096BYTES                              0x00D00000  
#define _IMAGE_SCN_ALIGN_8192BYTES                              0x00E00000  
// Unused                                    0x00F00000
#define _IMAGE_SCN_ALIGN_MASK                                   0x00F00000

#define _IMAGE_SCN_LNK_NRELOC_OVFL                              0x01000000  
#define _IMAGE_SCN_MEM_DISCARDABLE                              0x02000000 
#define _IMAGE_SCN_MEM_NOT_CACHED                               0x04000000 
#define _IMAGE_SCN_MEM_NOT_PAGED                                0x08000000  
#define _IMAGE_SCN_MEM_SHARED                                   0x10000000  
#define _IMAGE_SCN_MEM_EXECUTE                                  0x20000000  
#define _IMAGE_SCN_MEM_READ                                     0x40000000 
#define _IMAGE_SCN_MEM_WRITE                                    0x80000000  

#define _DELETE                                                 0x00010000L
#define _READ_CONTROL                                           0x00020000L
#define _WRITE_DAC                                              0x00040000L
#define _WRITE_OWNER                                            0x00080000L
#define _SYNCHRONIZE                                            0x00100000L
#define _STANDARD_RIGHTS_REQUIRED                               0x000F0000L
#define _STANDARD_RIGHTS_READ                                   _READ_CONTROL
#define _STANDARD_RIGHTS_WRITE                                  _READ_CONTROL
#define _STANDARD_RIGHTS_EXECUTE                                _READ_CONTROL
#define _STANDARD_RIGHTS_ALL                                    0x001F0000L
#define _SPECIFIC_RIGHTS_ALL                                    0x0000FFFFL
#define _ACCESS_SYSTEM_SECURITY                                 0x01000000L
#define _MAXIMUM_ALLOWED                                        0x02000000L
#define _GENERIC_READ                                           0x80000000L
#define _GENERIC_WRITE                                          0x40000000L
#define _GENERIC_EXECUTE                                        0x20000000L
#define _GENERIC_ALL                                            0x10000000L

#define _PROCESS_TERMINATE                                       0x0001
#define _PROCESS_CREATE_THREAD                                   0x0002
#define _PROCESS_SET_SESSIONID                                   0x0004
#define _PROCESS_VM_OPERATION                                    0x0008
#define _PROCESS_VM_READ                                         0x0010
#define _PROCESS_VM_WRITE                                        0x0020
#define _PROCESS_CREATE_PROCESS                                  0x0080
#define _PROCESS_SET_QUOTA                                       0x0100
#define _PROCESS_SET_INFORMATION                                 0x0200
#define _PROCESS_QUERY_INFORMATION                               0x0400
#define _PROCESS_SUSPEND_RESUME                                  0x0800
#define _PROCESS_QUERY_LIMITED_INFORMATION                       0x1000

#if (NTDDI_VERSION >= NTDDI_LONGHORN)
#define _PROCESS_ALL_ACCESS                      (_STANDARD_RIGHTS_REQUIRED | \
                                                 _SYNCHRONIZE | \
                                                 0xFFFF)
#else
#define _PROCESS_ALL_ACCESS                      (_STANDARD_RIGHTS_REQUIRED | \
                                                 _SYNCHRONIZE | \
                                                 0xFFF)
#endif

#define _IMAGE_DOS_SIGNATURE                                    0x5A4D      //MZ
#define _IMAGE_NT_SIGNATURE                                     0x50450000  //PE00

#define _IMAGE_SIZEOF_FILE_HEADER                               20
#define _IMAGE_SIZEOF_SECTION_HEADER                            40
#define _IMAGE_NUMBEROF_DIRECTORY_ENTRIES                       16
#define _IMAGE_SIZEOF_SHORT_NAME                                8

#define _IMAGE_NT_OPTIONAL_HDR32_MAGIC                          0x10b
#define _IMAGE_NT_OPTIONAL_HDR64_MAGIC                          0x20b

#define _IMAGE_ORDINAL_FLAG64                                   0x8000000000000000
#define _IMAGE_ORDINAL_FLAG32                                   0x80000000
#define _IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define _IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define _IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & _IMAGE_ORDINAL_FLAG64) != 0)
#define _IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & _IMAGE_ORDINAL_FLAG32) != 0)
//-----------------END Windows Defines-----------------//

//-----------------START Windows Base Types-----------------//
#if defined(_WIN64)
typedef unsigned __int64            _size_t;
typedef unsigned __int64            _ULONG_PTR;
typedef unsigned __int64            _ULONGLONG;
typedef __int64                     _LONGLONG;

typedef unsigned long long          _BASESIZE;
typedef unsigned long long* _PBASESIZE;
#else
typedef unsigned int                _size_t;
typedef unsigned long            _ULONG_PTR;
typedef unsigned __int32            _ULONGLONG; //NO SHITTY typedef double ULONGLONG;
typedef __int32                     _LONGLONG;  //NO SHITTY typedef double LONGLONG;

typedef unsigned long               _BASESIZE;
typedef unsigned long* _PBASESIZE;
#endif

typedef char                        _CHAR;
typedef unsigned char               _BYTE;
typedef unsigned char               _UCHAR;

typedef short                       _SHORT;
typedef unsigned short              _USHORT;
typedef unsigned short              _WORD;
typedef unsigned short              _WCHAR;    // wc,   16-bit UNICODE character
//typedef wchar_t  _WCHAR;

typedef int                         _BOOL;
typedef unsigned int                _UINT32;
typedef unsigned int                _UINT;

typedef long                        _LONG;
typedef unsigned long               _DWORD;
typedef unsigned long               _ULONG;

typedef unsigned __int64            _UINT64;
typedef unsigned __int64            _QWORD;

typedef void* _PVOID;
typedef void* _LPVOID;

typedef _PVOID                      _HANDLE;
typedef _ULONG_PTR                  _DWORD_PTR, * _PDWORD_PTR;
typedef _ULONG_PTR                  _SIZE_T, * _PSIZE_T;
typedef _ULONG* _PULONG;
typedef _HANDLE                     _HINSTANCE;
typedef _HINSTANCE                  _HMODULE;
typedef _HANDLE* _PHANDLE;
typedef _DWORD                      _ACCESS_MASK;
typedef _ACCESS_MASK* _PACCESS_MASK;
typedef _WCHAR* _PCWSTR;
typedef _WORD* _PWORD;
typedef _UCHAR* _PUCHAR;
typedef _BYTE                       _BOOLEAN;
typedef _DWORD* _PDWORD;
typedef _BYTE* _LPBYTE;

typedef _WCHAR* _LPCWSTR;
typedef _CHAR* _LPCSTR;//__nullterminated  
typedef _WCHAR* _PWSTR;//__nullterminated  
typedef _CHAR* _LPSTR;//__nullterminated  

typedef _LONG _KPRIORITY;

#ifdef UNICODE
typedef _LPCWSTR                    _LPCTSTR;
#else
typedef _LPCSTR                     _LPCTSTR;
#endif

#define _MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))

typedef _LONG _NTSTATUS;
typedef _LONG NTSTATUS;
#define _NT_SUCCESS(Status) ((_NTSTATUS)(Status) == _STATUS_SUCCESS)
//-----------------END Windows Base Types-----------------//

//-----------------START Windows Types-----------------//
typedef union LARGE_INTEGER
{
    struct {
        _DWORD LowPart;
        _LONG  HighPart;
    } _DUMMYSTRUCTNAME;
    struct {
        _DWORD LowPart;
        _LONG  HighPart;
    } u;
    _LONGLONG QuadPart;
} _LARGE_INTEGER, * _PLARGE_INTEGER;

typedef union ULARGE_INTEGER
{
    struct {
        _DWORD LowPart;
        _DWORD HighPart;
    } _DUMMYSTRUCTNAME;
    struct {
        _DWORD LowPart;
        _DWORD HighPart;
    } u;
    _ULONGLONG QuadPart;
} _ULARGE_INTEGER, * _PULARGE_INTEGER;

typedef struct _UNICODE_STRING
{
    _USHORT Length;
    _USHORT MaximumLength;
    _PWSTR  Buffer;
}_UNICODE_STRING, * _PUNICODE_STRING;


//-----------------END Windows Types-----------------//


typedef _NTSTATUS _NTAPI NTALLOCATEVIRTUALMEMORY(
    _HANDLE     ProcessHandle,
    _PVOID* BaseAddress,
    _ULONG_PTR  ZeroBits,
    _PSIZE_T    RegionSize,
    _ULONG      AllocationType,
    _ULONG      Protect
); typedef NTALLOCATEVIRTUALMEMORY* LPNTALLOCATEVIRTUALMEMORY;

typedef _NTSTATUS _NTAPI NTFREEVIRTUALMEMORY(
    _HANDLE     ProcessHandle,
    _PVOID* BaseAddress,
    _PSIZE_T    RegionSize,
    _ULONG      FreeType
); typedef NTFREEVIRTUALMEMORY* LPNTFREEVIRTUALMEMORY;


typedef _NTSTATUS _NTAPI NTWRITEVIRTUALMEMORY(
    _HANDLE ProcessHandle,
    _PVOID BaseAddress,
    _PVOID Buffer,
    _ULONG NumberOfBytesToWrite,
    _PULONG NumberOfBytesWritten _OPTIONAL
); typedef NTWRITEVIRTUALMEMORY* LPNTWRITEVIRTUALMEMORY;