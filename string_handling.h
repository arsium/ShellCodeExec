#pragma once
#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

_BOOLEAN	CompareUnicode(_PWSTR, _PWSTR);
char*		Separator(char*);
char*		ReverseSeparator(char*);
char		ToLowerA(char);
_WCHAR		ToLowerW(_WCHAR);
int			StringLengthA(char*);
int			StringLengthW(_WCHAR*);
_BOOL		StringMatches(_WCHAR*, _WCHAR*);
_WCHAR*		CharToWCharT(char*);
_BOOLEAN	CompareAnsi(char*, char*);