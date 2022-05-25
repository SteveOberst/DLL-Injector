#include "injector.h"
#include <fstream>

// ================ Internal function defs ================
namespace Internal
{
    bool ManualMap(
            HANDLE                 hProc,
            MANUAL_MAPPING_DATA*    data,
            BYTE*                  pSrcData,
            IMAGE_NT_HEADERS*      pOldNtHeader,
            IMAGE_OPTIONAL_HEADER* pOldOptHeader,
            IMAGE_FILE_HEADER*     pOldFileHeader,
            BYTE*                  pTargetBase
            )
    {
        auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for(UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
        {
            if(pSectionHeader->SizeOfRawData)
            {
                if(!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
                {
                    return false;
                }
            }
        }

        return true;
    }

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

    void __stdcall Shellcode(MANUAL_MAPPING_DATA* pMappingData)
    {
        if(!pMappingData)
        {
            return;
        }

        BYTE* pBase = reinterpret_cast<BYTE*>(pMappingData);
        auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pMappingData)->e_lfanew)->OptionalHeader;

        auto _LoadLibraryA = pMappingData->pLoadLibraryA;
        auto _GetProcAddress = pMappingData->pGetProcAddress;
        auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

        BYTE* pLocationDelta = pBase - pOpt->ImageBase;
        if(pLocationDelta)
        {
            if(!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            {
                auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                while(pRelocData->VirtualAddress)
                {
                    UINT entries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
                    for(UINT i = 0; i != entries; ++i, ++pRelativeInfo)
                    {
                        if(RELOC_FLAG(*pRelativeInfo))
                        {
                            UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                            *pPatch += reinterpret_cast<UINT_PTR>(pLocationDelta);
                        }
                    }
                    pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
                }
            }
        }

        if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        {
            auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            while(pImportDesc->Name)
            {
                char* szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
                HINSTANCE hDll = _LoadLibraryA(szMod);
                ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);
                ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

                if(!pThunkRef)
                {
                    pThunkRef = pFuncRef;
                }

                for(; *pThunkRef; ++pThunkRef, ++ pFuncRef)
                {
                    if(IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                    {
                        *pThunkRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                    }
                    else
                    {
                        auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                        *pFuncRef = _GetProcAddress(hDll, pImport->Name);
                    }
                }
                ++pImportDesc;
            }
        }
        if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
        {
            auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
            auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
            for(; pCallback && *pCallback; ++pCallback)
            {
                (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
            }
        }

        _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
        pMappingData->hMod = reinterpret_cast<HINSTANCE>(pBase);
    }
}

// ================ Manual Mapping defs ================

InjectionResult ManualMapInjector::inject(DWORD dwProcId, const char* pDllPath)
{
    BYTE*                  pSrcData;
    IMAGE_NT_HEADERS*      pOldNtHeader;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader;
    IMAGE_FILE_HEADER*     pOldFileHeader;
    BYTE*                  pTargetBase;
    InjectionResult        result { INJECTION_RESULT_ERROR };

    HANDLE hProc = Win::GetProcessHandle_s(PROCESS_ALL_ACCESS, FALSE, dwProcId);

    if(hProc == INVALID_HANDLE_VALUE)
    {
        result.error_msg = "Encountered error whilst opening process.";
        return result;
    }

    if(!GetFileAttributesA(pDllPath))
    {
        result.error_msg = "The specified file does not exist.";
        return result;
    }

    std::ifstream file(pDllPath, std::ios::binary | std::ios::ate);

    if(file.fail())
    {
        file.close();
        result.error_msg = "Encountered error whilst reading file.";
        return result;
    }

    auto size = file.tellg();

    if(size < 0x1000)
    {
        file.close();
        result.error_msg = "Invalid file size.";
        return result;
    }

    pSrcData = new BYTE[static_cast<UINT_PTR>(size)];
    if(!pSrcData)
    {
        file.close();
        result.error_msg = "Memory allocation failed.";
        return result;
    }

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(pSrcData), size);

    if(reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
    {
        file.close();
        result.error_msg = "Bad file selected.";
        return result;
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
    if(pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        delete[] pSrcData;
        result.error_msg = "Invalid platform architecture.";
        return result;
    }
#else
    if(pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        delete[] pSrcData;
        result.error_msg = "Invalid platform architecture.";
        return result;
    }
#endif
    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if(!pTargetBase)
    {
        pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if(!pTargetBase)
        {
            delete[] pSrcData;
            result.error_msg = "Memory allocation failed.";
            return result;
        }
    }

    Internal::MANUAL_MAPPING_DATA data { 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = reinterpret_cast<Internal::f_GetProcAddress>(GetProcAddress);

    if(!Internal::ManualMap(hProc, &data, pSrcData, pOldNtHeader, pOldOptHeader, pOldFileHeader, pTargetBase))
    {
        delete[] pSrcData;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE); // Not sure whether this one's right
        result.error_msg = "Manual mapping failed.";
        return result;
    }

    memcpy(pSrcData, &data, sizeof(data));
    WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);
    delete[] pSrcData;
    void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if(!pShellcode)
    {
        result.error_msg = "Shellcode memory allocation failed.";
        return result;
    }

    WriteProcessMemory(hProc, pShellcode, (LPCVOID) Internal::Shellcode, 0x1000, nullptr);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
    if(!hThread)
    {
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        result.error_msg = "Manual mapping failed.";
        return result;
    }

    HINSTANCE hCheck = NULL;
    while(!hCheck)
    {
        Internal::MANUAL_MAPPING_DATA data_checked {0};
        ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;
    }

    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
    CloseHandle(hThread);
    result.status = INJECTION_RESULT_OK;
    return result;
}

// ================ LoadLibrary defs ================

InjectionResult LoadLibraryInjector::inject(DWORD dwProcId, const char* pDllPath)
{
    HANDLE hProc = Win::GetProcessHandle_s(PROCESS_ALL_ACCESS, FALSE, dwProcId);
    InjectionResult result { INJECTION_RESULT_ERROR };

    if(!hProc)
    {
        result.error_msg = "Failed to get handle of process.";
        return result;
    }

    void* pMemBuf = VirtualAllocEx(hProc, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(!pMemBuf)
    {
        result.error_msg = "Error whilst allocating memory to the target process.";
        return result;
    }

    WINBOOL success = WriteProcessMemory(hProc, pMemBuf, pDllPath, strlen(pDllPath) + 1, 0);
    if(!success)
    {
        result.error_msg = "Error whilst allocating memory to the target process.";
        return result;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, NULL, LPTHREAD_START_ROUTINE(LoadLibraryA), pMemBuf, NULL, nullptr);
    if (!hThread)
    {
        VirtualFreeEx(hProc, pMemBuf, NULL, MEM_RELEASE);
        result.error_msg = "Error whilst creating remote thread.";
        return result;
    }

    VirtualFreeEx(hProc, pMemBuf, NULL, MEM_RELEASE);
    CloseHandle(hProc);
    result.status = INJECTION_RESULT_OK;
    return result;
}
