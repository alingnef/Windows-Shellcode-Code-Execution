#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef DWORD (WINAPI *GetPidFn)(void);

int main(void) {
    HMODULE mod = LoadLibraryW(L"kernel32.dll");
    if (!mod) {
        printf("LoadLibraryW failed: %lu\n", GetLastError());
        return 1;
    }

    FARPROC p = GetProcAddress(mod, "GetCurrentProcessId");
    if (!p) {
        printf("GetProcAddress failed: %lu\n", GetLastError());
        FreeLibrary(mod);
        return 1;
    }

    GetPidFn getPid = (GetPidFn)p;
    printf("Current PID: %lu\n", getPid());
    FreeLibrary(mod);
    return 0;
}