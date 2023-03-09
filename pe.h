#pragma once
#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

typedef struct IMAGE_DOS_HEADER
{
    _WORD   e_magic;
    _WORD   e_cblp;
    _WORD   e_cp;
    _WORD   e_crlc;
    _WORD   e_cparhdr;
    _WORD   e_minalloc;
    _WORD   e_maxalloc;
    _WORD   e_ss;
    _WORD   e_sp;
    _WORD   e_csum;
    _WORD   e_ip;
    _WORD   e_cs;
    _WORD   e_lfarlc;
    _WORD   e_ovno;
    _WORD   e_res[4];
    _WORD   e_oemid;
    _WORD   e_oeminfo;
    _WORD   e_res2[10];
    _LONG   e_lfanew;
} _IMAGE_DOS_HEADER, * _PIMAGE_DOS_HEADER;

typedef struct IMAGE_DATA_DIRECTORY
{
    _DWORD   VirtualAddress;
    _DWORD   Size;
} _IMAGE_DATA_DIRECTORY, * _PIMAGE_DATA_DIRECTORY;

typedef struct IMAGE_OPTIONAL_HEADER
{
    _WORD    Magic;
    _BYTE    MajorLinkerVersion;
    _BYTE    MinorLinkerVersion;
    _DWORD   SizeOfCode;
    _DWORD   SizeOfInitializedData;
    _DWORD   SizeOfUninitializedData;
    _DWORD   AddressOfEntryPoint;
    _DWORD   BaseOfCode;
    _DWORD   BaseOfData;
    _DWORD   ImageBase;
    _DWORD   SectionAlignment;
    _DWORD   FileAlignment;
    _WORD    MajorOperatingSystemVersion;
    _WORD    MinorOperatingSystemVersion;
    _WORD    MajorImageVersion;
    _WORD    MinorImageVersion;
    _WORD    MajorSubsystemVersion;
    _WORD    MinorSubsystemVersion;
    _DWORD   Win32VersionValue;
    _DWORD   SizeOfImage;
    _DWORD   SizeOfHeaders;
    _DWORD   CheckSum;
    _WORD    Subsystem;
    _WORD    DllCharacteristics;
    _DWORD   SizeOfStackReserve;
    _DWORD   SizeOfStackCommit;
    _DWORD   SizeOfHeapReserve;
    _DWORD   SizeOfHeapCommit;
    _DWORD   LoaderFlags;
    _DWORD   NumberOfRvaAndSizes;
    _IMAGE_DATA_DIRECTORY DataDirectory[_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} _IMAGE_OPTIONAL_HEADER32, * _PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_OPTIONAL_HEADER64
{
    _WORD        Magic;
    _BYTE        MajorLinkerVersion;
    _BYTE        MinorLinkerVersion;
    _DWORD       SizeOfCode;
    _DWORD       SizeOfInitializedData;
    _DWORD       SizeOfUninitializedData;
    _DWORD       AddressOfEntryPoint;
    _DWORD       BaseOfCode;
    _ULONGLONG   ImageBase;
    _DWORD       SectionAlignment;
    _DWORD       FileAlignment;
    _WORD        MajorOperatingSystemVersion;
    _WORD        MinorOperatingSystemVersion;
    _WORD        MajorImageVersion;
    _WORD        MinorImageVersion;
    _WORD        MajorSubsystemVersion;
    _WORD        MinorSubsystemVersion;
    _DWORD       Win32VersionValue;
    _DWORD       SizeOfImage;
    _DWORD       SizeOfHeaders;
    _DWORD       CheckSum;
    _WORD        Subsystem;
    _WORD        DllCharacteristics;
    _ULONGLONG   SizeOfStackReserve;
    _ULONGLONG   SizeOfStackCommit;
    _ULONGLONG   SizeOfHeapReserve;
    _ULONGLONG   SizeOfHeapCommit;
    _DWORD       LoaderFlags;
    _DWORD       NumberOfRvaAndSizes;
    _IMAGE_DATA_DIRECTORY DataDirectory[_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} _IMAGE_OPTIONAL_HEADER64, * _PIMAGE_OPTIONAL_HEADER64;


#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)
#define _ALIGNMENT_MACHINE
#define _UNALIGNED __unaligned
#if defined(_WIN64)
#define _UNALIGNED64 __unaligned
#else
#define _UNALIGNED64
#endif
#else
#undef _ALIGNMENT_MACHINE
#define _UNALIGNED
#define _UNALIGNED64
#endif

typedef struct IMAGE_FILE_HEADER
{
    _WORD    Machine;
    _WORD    NumberOfSections;
    _DWORD   TimeDateStamp;
    _DWORD   PointerToSymbolTable;
    _DWORD   NumberOfSymbols;
    _WORD    SizeOfOptionalHeader;
    _WORD    Characteristics;
} _IMAGE_FILE_HEADER, * _PIMAGE_FILE_HEADER;

typedef struct IMAGE_NT_HEADERS64
{
    _DWORD Signature;
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} _IMAGE_NT_HEADERS64, * _PIMAGE_NT_HEADERS64;

typedef struct IMAGE_NT_HEADERS
{
    _DWORD Signature;
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} _IMAGE_NT_HEADERS32, * _PIMAGE_NT_HEADERS32;

typedef struct IMAGE_SECTION_HEADER {
    _BYTE    Name[_IMAGE_SIZEOF_SHORT_NAME];
    union {
        _DWORD   PhysicalAddress;
        _DWORD   VirtualSize;
    } Misc;
    _DWORD   VirtualAddress;
    _DWORD   SizeOfRawData;
    _DWORD   PointerToRawData;
    _DWORD   PointerToRelocations;
    _DWORD   PointerToLinenumbers;
    _WORD    NumberOfRelocations;
    _WORD    NumberOfLinenumbers;
    _DWORD   Characteristics;
} _IMAGE_SECTION_HEADER, * _PIMAGE_SECTION_HEADER;

typedef struct IMAGE_IMPORT_DESCRIPTOR
{
    union {
        _DWORD   Characteristics;            // 0 for terminating null import descriptor
        _DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    _DWORD   TimeDateStamp;                  // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)

    _DWORD   ForwarderChain;                 // -1 if no forwarders
    _DWORD   Name;
    _DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} _IMAGE_IMPORT_DESCRIPTOR;
typedef _IMAGE_IMPORT_DESCRIPTOR _UNALIGNED* _PIMAGE_IMPORT_DESCRIPTOR;

//@[comment("MVI_tracked")]
typedef struct IMAGE_IMPORT_BY_NAME
{
    _WORD    Hint;
    _CHAR   Name[1];
} _IMAGE_IMPORT_BY_NAME, * _PIMAGE_IMPORT_BY_NAME;

//@[comment("MVI_tracked")]
typedef struct IMAGE_THUNK_DATA64
{
    union {
        _ULONGLONG ForwarderString;  // PBYTE 
        _ULONGLONG Function;         // PDWORD
        _ULONGLONG Ordinal;
        _ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} _IMAGE_THUNK_DATA64;
typedef _IMAGE_THUNK_DATA64* _PIMAGE_THUNK_DATA64;

//@[comment("MVI_tracked")]
typedef struct IMAGE_THUNK_DATA32
{
    union {
        _DWORD ForwarderString;      // PBYTE 
        _DWORD Function;             // PDWORD
        _DWORD Ordinal;
        _DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} _IMAGE_THUNK_DATA32;
typedef _IMAGE_THUNK_DATA32* _PIMAGE_THUNK_DATA32;

typedef struct IMAGE_TLS_DIRECTORY64
{
    _ULONGLONG StartAddressOfRawData;
    _ULONGLONG EndAddressOfRawData;
    _ULONGLONG AddressOfIndex;         // PDWORD
    _ULONGLONG AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
    _DWORD SizeOfZeroFill;
    union {
        _DWORD Characteristics;
        struct {
            _DWORD Reserved0 : 20;
            _DWORD Alignment : 4;
            _DWORD Reserved1 : 8;
        } _DUMMYSTRUCTNAME;
    } _DUMMYUNIONNAME;

} _IMAGE_TLS_DIRECTORY64;

typedef _IMAGE_TLS_DIRECTORY64* _PIMAGE_TLS_DIRECTORY64;

typedef struct IMAGE_TLS_DIRECTORY32
{
    _DWORD   StartAddressOfRawData;
    _DWORD   EndAddressOfRawData;
    _DWORD   AddressOfIndex;             // PDWORD
    _DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    _DWORD   SizeOfZeroFill;
    union {
        _DWORD Characteristics;
        struct {
            _DWORD Reserved0 : 20;
            _DWORD Alignment : 4;
            _DWORD Reserved1 : 8;
        } _DUMMYSTRUCTNAME;
    } _DUMMYUNIONNAME;

} _IMAGE_TLS_DIRECTORY32;
typedef _IMAGE_TLS_DIRECTORY32* _PIMAGE_TLS_DIRECTORY32;

typedef struct IMAGE_BASE_RELOCATION
{
    _DWORD   VirtualAddress;
    _DWORD   SizeOfBlock;
    //  WORD    TypeOffset[1];
} _IMAGE_BASE_RELOCATION;
typedef _IMAGE_BASE_RELOCATION _UNALIGNED* _PIMAGE_BASE_RELOCATION;

typedef struct IMAGE_EXPORT_DIRECTORY
{
    _DWORD   Characteristics;
    _DWORD   TimeDateStamp;
    _WORD    MajorVersion;
    _WORD    MinorVersion;
    _DWORD   Name;
    _DWORD   Base;
    _DWORD   NumberOfFunctions;
    _DWORD   NumberOfNames;
    _DWORD   AddressOfFunctions;     // RVA from base of image
    _DWORD   AddressOfNames;         // RVA from base of image
    _DWORD   AddressOfNameOrdinals;  // RVA from base of image
} _IMAGE_EXPORT_DIRECTORY, * _PIMAGE_EXPORT_DIRECTORY;


#ifdef _WIN64
typedef _IMAGE_NT_HEADERS64                 _IMAGE_NT_HEADERS;
typedef _PIMAGE_NT_HEADERS64                _PIMAGE_NT_HEADERS;
typedef _IMAGE_OPTIONAL_HEADER64            _IMAGE_OPTIONAL_HEADER;
typedef _PIMAGE_OPTIONAL_HEADER64           _PIMAGE_OPTIONAL_HEADER;
#define _IMAGE_NT_OPTIONAL_HDR_MAGIC        _IMAGE_NT_OPTIONAL_HDR64_MAGIC

#define _IMAGE_ORDINAL_FLAG                 _IMAGE_ORDINAL_FLAG64
#define _IMAGE_ORDINAL(Ordinal)             _IMAGE_ORDINAL64(Ordinal)
typedef _IMAGE_THUNK_DATA64                 _IMAGE_THUNK_DATA;
typedef _PIMAGE_THUNK_DATA64                _PIMAGE_THUNK_DATA;
#define _IMAGE_SNAP_BY_ORDINAL(Ordinal)     _IMAGE_SNAP_BY_ORDINAL64(Ordinal)
typedef _IMAGE_TLS_DIRECTORY64              _IMAGE_TLS_DIRECTORY;
typedef _PIMAGE_TLS_DIRECTORY64             _PIMAGE_TLS_DIRECTORY;

#else
typedef _IMAGE_NT_HEADERS32                 _IMAGE_NT_HEADERS;
typedef _PIMAGE_NT_HEADERS32                _PIMAGE_NT_HEADERS;
typedef _IMAGE_OPTIONAL_HEADER32            _IMAGE_OPTIONAL_HEADER;
typedef _PIMAGE_OPTIONAL_HEADER32           _PIMAGE_OPTIONAL_HEADER;
#define _IMAGE_NT_OPTIONAL_HDR_MAGIC        _IMAGE_NT_OPTIONAL_HDR32_MAGIC

#define _IMAGE_ORDINAL_FLAG                 _IMAGE_ORDINAL_FLAG32
#define _IMAGE_ORDINAL(Ordinal)             _IMAGE_ORDINAL32(Ordinal)
typedef _IMAGE_THUNK_DATA32                 _IMAGE_THUNK_DATA;
typedef _PIMAGE_THUNK_DATA32                _PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)      _IMAGE_SNAP_BY_ORDINAL32(Ordinal)
typedef _IMAGE_TLS_DIRECTORY32              _IMAGE_TLS_DIRECTORY;
typedef _PIMAGE_TLS_DIRECTORY32             _PIMAGE_TLS_DIRECTORY;
#endif