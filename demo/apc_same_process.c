#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

VOID CALLBACK OnApc(ULONG_PTR value) {
    printf("APC executed: PID=%lu TID=%lu value=%llu\n",
           GetCurrentProcessId(), GetCurrentThreadId(),
           (unsigned long long)value);
}

DWORD WINAPI AlertableWorker(LPVOID unused) {
    (void)unused;
    printf("Worker thread %lu entering alertable wait\n",
           GetCurrentThreadId());
    DWORD result = SleepEx(5000, TRUE);
    printf("SleepEx result: %lu\n", result);
    return 0;
}

int main(void) {
    HANDLE th = CreateThread(NULL, 0, AlertableWorker,
                             NULL, CREATE_SUSPENDED, NULL);
    if (!th) return 1;

    if (!QueueUserAPC(OnApc, th, (ULONG_PTR)42)) {
        printf("QueueUserAPC failed: %lu\n", GetLastError());
        CloseHandle(th);
        return 1;
    }

    if (ResumeThread(th) == (DWORD)-1) {
        printf("ResumeThread failed: %lu\n", GetLastError());
        CloseHandle(th);
        return 1;
    }

    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return 0;
}