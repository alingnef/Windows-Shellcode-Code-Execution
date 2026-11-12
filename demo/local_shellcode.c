#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef int (*ShellFn)(void);

int main(void) {
    const unsigned char code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3
    };

    void *p = VirtualAlloc(NULL, sizeof(code),
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
    if (!p) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    memcpy(p, code, sizeof(code));

    DWORD previous = 0;
    if (!VirtualProtect(p, sizeof(code),
                        PAGE_EXECUTE_READ, &previous)) {
        printf("VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(p, 0, MEM_RELEASE);
        return 1;
    }

    if (!FlushInstructionCache(GetCurrentProcess(), p, sizeof(code))) {
        printf("FlushInstructionCache failed: %lu\n", GetLastError());
        VirtualFree(p, 0, MEM_RELEASE);
        return 1;
    }

    int result = ((ShellFn)p)();
    printf("Shellcode returned: %d\n", result);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}