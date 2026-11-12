#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(void) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessW(
            L"C:\\Windows\\System32\\whoami.exe",
            NULL, NULL, NULL, FALSE, 0,
            NULL, NULL, &si, &pi)) {
        printf("CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Parent PID: %lu\n", GetCurrentProcessId());
    printf("Child PID: %lu\n", pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code)) {
        printf("Exit code: %lu\n", code);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
