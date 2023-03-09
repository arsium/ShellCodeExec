#pragma once

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

#include "windeftypes.h"
#include "resolver.h"
#include "peb.h"
#include "pe.h"
#include "utils.h"
#include "string_handling.h"

static _PWSTR dll = L"ntdll.dll\0";
static char ntAllocate[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', '\0' };//"NtAllocateVirtualMemory\0";
static char ntWriteVirtual[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };//"NtWriteVirtualMemory\0";
static char ntProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };//"NtProtectVirtualMemory\0";
static char ntFree[] = { 'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };//"NtFreeVirtualMemory\0";