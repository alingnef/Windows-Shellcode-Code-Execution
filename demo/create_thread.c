#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

DWORD WINAPI Worker(LPVOID context) {
    int n = *(const int *)context;
    printf("Worker: PID=%lu TID=%lu value=%d\n",
           GetCurrentProcessId(), GetCurrentThreadId(), n);
    return (DWORD)(n + 1);
}

int main(void) {
    int value = 41;
    DWORD tid = 0;

    HANDLE th = CreateThread(NULL, 0, Worker,
                             &value, 0, &tid);
    if (!th) {
        printf("CreateThread failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Main: PID=%lu TID=%lu; new TID=%lu\n",
           GetCurrentProcessId(), GetCurrentThreadId(), tid);

    WaitForSingleObject(th, INFINITE);
    DWORD exitCode = 0;
    if (GetExitCodeThread(th, &exitCode))
        printf("Worker exit code: %lu\n", exitCode);
    CloseHandle(th);
    return 0;
}