#ifndef INJECTOR_H
#define INJECTOR_H

#endif //INJECTOR_H

#include "winutil.h"

#include <map>

typedef unsigned int INJECTION_RESULT_STATUS;

static INJECTION_RESULT_STATUS INJECTION_RESULT_OK = 0x1;
static INJECTION_RESULT_STATUS  INJECTION_RESULT_ERROR = 0x2;

enum class InjectionMethod
{
    MANUAL_MAP,
    LOAD_LIBRARY
};

struct InjectionResult
{
    INJECTION_RESULT_STATUS status;
    const char* error_msg;
};

class Injector
{
private:
    const InjectionMethod& method;

public:
    Injector(const InjectionMethod& method) : method { method }
    {}

    ~Injector() {}

    virtual InjectionResult inject(DWORD dwProcId, const char* pDllPath) = 0;
};

class ManualMapInjector : public Injector
{
public:
    ManualMapInjector(const InjectionMethod& method) : Injector(method) {}

    ~ManualMapInjector(){}

    InjectionResult inject(DWORD dwProcId, const char* pDllPath);
};

class LoadLibraryInjector : public Injector
{
public:
    LoadLibraryInjector(const InjectionMethod& method) : Injector(method) {}

    ~LoadLibraryInjector(){}

    InjectionResult inject(DWORD dwProcId, const char* pDllPath);
};

// ================ Internal Functions ================
namespace Internal
{

    // ================ Manual Mapping ================
    using f_LoadLibraryA    = HINSTANCE (WINAPI*)(const char* lpLibFilename);
    using f_GetProcAddress  = UINT_PTR  (WINAPI*)(HINSTANCE hModule, const char* lpProcName);
    using f_DLL_ENTRY_POINT = BOOL      (WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

    struct MANUAL_MAPPING_DATA
    {
        f_LoadLibraryA   pLoadLibraryA;
        f_GetProcAddress pGetProcAddress;
        HINSTANCE        hMod;
    };

    // The manual mapping injection would've not been possible without
    // some awesome resources on the guidedhacking.com forum.
    bool ManualMap(
        HANDLE                 hProc,
        MANUAL_MAPPING_DATA*   pMappingData,
        BYTE*                  pSrcData,
        IMAGE_NT_HEADERS*      pOldNtHeader,
        IMAGE_OPTIONAL_HEADER* pOldOptHeader,
        IMAGE_FILE_HEADER*     pOldFileHeader,
        BYTE*                  pTargetBase
    );

    void __stdcall Shellcode(MANUAL_MAPPING_DATA* pMappingData);

    // ================ LoadLibrary ================
}

static const std::map<InjectionMethod, Injector*> injectors =
{
    { InjectionMethod::MANUAL_MAP, new ManualMapInjector(InjectionMethod::MANUAL_MAP) },
    { InjectionMethod::LOAD_LIBRARY, new LoadLibraryInjector(InjectionMethod::LOAD_LIBRARY) }
};

static Injector* get_by_type(InjectionMethod method)
{
    return injectors.at(method);
}
