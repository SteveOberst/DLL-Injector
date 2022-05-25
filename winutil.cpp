#include "winutil.h"

namespace Win
{
    std::list<PROCESSENTRY32> get_running_processes() {

        std::list<PROCESSENTRY32> proc_list;
        HANDLE hProcessSnap;
        PROCESSENTRY32 pe32;
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            return std::list<PROCESSENTRY32>();
        }
        else
        {
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hProcessSnap, &pe32))
            { // Gets first running process
                while (Process32Next(hProcessSnap, &pe32))
                {
                    proc_list.push_back(pe32);
                }
                CloseHandle(hProcessSnap);
            }
        }
        return proc_list;
    }

    HANDLE GetProcessHandle_s(unsigned int flags, WINBOOL bInheritHandle, DWORD dwProcId)
    {
        HANDLE hProc = OpenProcess(flags, bInheritHandle, dwProcId);
        if(!hProc)
        {
            return INVALID_HANDLE_VALUE;
        }
        return hProc;
    }
}
