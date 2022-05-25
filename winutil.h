#ifndef WINUTIL_H
#define WINUTIL_H

#include <list>
#include <string>

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

namespace Win
{
    std::list<PROCESSENTRY32> get_running_processes();

    HANDLE GetProcessHandle_s(unsigned int flags, WINBOOL bInheritHandle, DWORD dwProcId);
}

#endif // WINUTIL_H
