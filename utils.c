#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

_PVOID MallocCustom(_PSIZE_T size)
{
    LPNTALLOCATEVIRTUALMEMORY pNtAllocate = GetProcedureAddressNt(ntAllocate);
    _PVOID pAllocated = NULL_PTR;
    pNtAllocate((_HANDLE)(-1), &pAllocated, 0, size, _MEM_RESERVE | _MEM_COMMIT, _PAGE_READWRITE);
    return pAllocated;
}