#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

_LPVOID _CBASE NtCurrentPeb(void)
{
#if defined(_WIN64)
    _UINT64 pPebLocation = __readgsqword(0x60);
    return (_LPVOID)pPebLocation;
#else
    _UINT32 pPebLocation = __readfsdword(0x30);
    return (_LPVOID)pPebLocation;
#endif
}

_PVOID _CBASE GetModuleBaseAddress(_PWSTR name)
{
    _PPEB pPeb = (_PPEB)NtCurrentPeb();
    _PPEB_LDR_DATA pLdrData = (_PPEB_LDR_DATA)pPeb->LdrData;

    for (_PLDR_DATA_ENTRY pLdrDataEntry = (_PLDR_DATA_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->BaseAddress != NULL_PTR; pLdrDataEntry = (_PLDR_DATA_ENTRY)pLdrDataEntry->InLoadOrderModuleList.Flink)
    {
        if (CompareUnicode(name, pLdrDataEntry->BaseDllName.Buffer))
            return pLdrDataEntry->BaseAddress;
    }
    return NULL_PTR;
}

_LPVOID _CBASE GetProcedureAddressNt(char* sProcName)
{
    _DWORD_PTR pBaseAddr = (_DWORD_PTR)GetModuleBaseAddress(dll);

    _IMAGE_DOS_HEADER* pDosHdr = (_IMAGE_DOS_HEADER*)pBaseAddr;
    _IMAGE_NT_HEADERS* pNTHdr = (_IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    _IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    _IMAGE_DATA_DIRECTORY* pExportDataDir = (_IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[_IMAGE_DIRECTORY_ENTRY_EXPORT]);
    _IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (_IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    _DWORD* pEAT = (_DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    _DWORD* pFuncNameTbl = (_DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    _WORD* pHintsTbl = (_WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    if (((_DWORD_PTR)sProcName >> 16) == 0)
    {
        _WORD ordinal = (_WORD)sProcName & 0xFFFF;	
        _DWORD Base = pExportDirAddr->Base;			

        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL_PTR;

        return (_PVOID)(pBaseAddr + (_DWORD_PTR)pEAT[ordinal - Base]);
    }
    else
    {
        for (_DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++)
        {
            char* sTmpFuncName = (char*)(pBaseAddr + (_DWORD_PTR)pFuncNameTbl[i]);

            if (CompareAnsi(sProcName, sTmpFuncName) == TRUE)
            {
                return (_LPVOID)(pBaseAddr + (_DWORD_PTR)pEAT[pHintsTbl[i]]);
            }
        }
    }
}