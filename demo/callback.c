#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM state) {
    int *counter = (int *)state;
    wchar_t title[256];

    if (GetWindowTextW(hwnd, title, 256) > 0) {
        wprintf(L"[%d] %ls\n", ++(*counter), title);
    }
    return (*counter < 5) ? TRUE : FALSE;
}

int main(void) {
    int count = 0;
    BOOL complete = EnumWindows(EnumWindowCallback, (LPARAM)&count);
    wprintf(L"Enumerated windows with titles: %d\n", count);
    (void)complete; // FALSE cũng có thể là do callback chủ động dừng.
    return 0;
}