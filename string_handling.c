#include "global.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

_BOOLEAN CompareUnicode(_PWSTR u1, _PWSTR u2)
{
    for (int i = 0; i < StringLengthW(u1); i++)
    {
        if (ToLowerW(u1[i]) != ToLowerW(u2[i]))
            return FALSE;
    }
    return TRUE;
}

_BOOLEAN CompareAnsi(char* u1, char* u2)
{
    for (int i = 0; i < StringLengthA(u1); i++)
    {
        if (ToLowerA(u1[i]) != ToLowerA(u2[i]))
            return FALSE;
    }
    return TRUE;
}

char* Separator(char* full_name)
{
    _size_t len = strlen(full_name);

    for (_size_t i = 0; i < len; i++)
    {
        if (full_name[i] == '.')
        {
            return &full_name[i + 1];
        }
    }
    return NULL_PTR;
}

char* ReverseSeparator(char* full_name)
{
    _size_t len = StringLengthA(full_name);

    int indexPoint = 5;//. d l l \0

    for (_size_t i = 0; i < len; i++)
    {
        if (full_name[i] == '.')
        {
            indexPoint += i;
            break;
        }
    }
    _DWORD_PTR size = (_DWORD_PTR)((sizeof(char) * indexPoint));
    char* name = (char*)MallocCustom(&size);
    if (name != NULL_PTR)
    {
        for (int i = 0; i < indexPoint; i++)
            name[i] = full_name[i];

        name[indexPoint - 5] = '.';
        name[indexPoint - 4] = 'd';
        name[indexPoint - 3] = 'l';
        name[indexPoint - 2] = 'l';
        name[indexPoint - 1] = '\0';
        return name;
    }
    return NULL_PTR;
}

_WCHAR* CharToWCharT(char* str)
{
    int length = StringLengthA(str);

    _DWORD_PTR size = (_DWORD_PTR)(sizeof(_WCHAR) * length + 2);
    _WCHAR* wStr = (_WCHAR*)MallocCustom(&size);

    if (wStr != NULL_PTR)
    {
        for (int i = 0; i < length; i++)
        {
            wStr[i] = (_WCHAR)(str[i]);
        }
        wStr[length] = '\0';
        return (_WCHAR*)wStr;
    }
    return NULL_PTR;
}

_WCHAR ToLowerW(_WCHAR ch)
{
    if (ch > 0x40 && ch < 0x5B)
    {
        return ch + 0x20;
    }
    return ch;
}

char ToLowerA(char ch)
{
    if (ch > 96 && ch < 123)
    {
        ch -= 32;
    }
    return ch;
}

int StringLengthA(char* str)
{
    int length;
    for (length = 0; str[length] != '\0'; length++) {}
    return length;
}

int StringLengthW(_WCHAR* str) {
    int length;
    for (length = 0; str[length] != '\0'; length++) {}
    return length;
}

_BOOL StringMatches(_WCHAR* str1, _WCHAR* str2)
{
    if (str1 == NULL_PTR || str2 == NULL_PTR || StringLengthW(str1) != StringLengthW(str2))
    {
        return FALSE;
    }

    for (int i = 0; str1[i] != '\0' && str2[i] != '\0'; i++)
    {
        if (ToLowerW(str1[i]) != ToLowerW(str2[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}