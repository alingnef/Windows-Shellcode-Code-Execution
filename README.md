# Windows Shellcode & Code Execution

Repository ghi chép và thực hành các **cơ chế thực thi mã trên Windows**, từ việc tạo process thông thường đến thực thi shellcode trong bộ nhớ. Mục tiêu là hiểu **mã được nạp ở đâu, bằng cách nào và được kích hoạt thực thi ra sao** - thay vì đồng nhất mọi kỹ thuật với *Process Injection*.

## Nội dung nghiên cứu

- **Standard PE Execution:** tạo process con bằng `CreateProcessW`.
- **Local Shellcode Execution:** cấp phát bộ nhớ, ghi machine code, thiết lập quyền thực thi và gọi qua function pointer.
- **Thread / Fiber Execution:** các ngữ cảnh thực thi trong cùng process.
- **Callback-based Execution:** Windows gọi lại hàm thông qua `EnumWindows`.
- **APC-based Execution:** xếp lịch callback vào thread bằng `QueueUserAPC`.
- **DLL / Module Execution:** `LoadLibraryW`, `GetProcAddress` và cơ chế nạp DLL.
- **Manual / Reflective PE Loading:** nguyên lý PE loader, relocation, IAT và PE-to-Shellcode.
- **Process Injection:** tổng quan các nhóm kỹ thuật và cách phân biệt với local execution.
- **Windows Internals & Detection:** process, thread, virtual memory, DEP, CFG, ASLR và dấu hiệu quan sát khi phân tích.

## Ví dụ thực hành

| File ví dụ | Nội dung |
|---|---|
| `create_process.c` | Tạo process con và lấy PID, exit code |
| `local_shellcode.c` | Chạy mã máy x64 trả về `42` trong process hiện tại |
| `create_thread.c` | Thực thi hàm bằng thread mới |
| `callback.c` | Liệt kê cửa sổ bằng `EnumWindows` và callback |
| `apc_same_process.c` | Minh họa user-mode APC trong cùng process |
| `loadlibrary.c` | Nạp DLL và gọi một hàm export |

Các tên file trên là những ví dụ được trình bày trong tài liệu; có thể tổ chức source vào thư mục riêng khi đưa lên GitHub.

## Biên dịch và chạy

**Yêu cầu:** Windows x64, MinGW-w64 GCC hoặc MSVC (Visual Studio C++ Build Tools).

Ví dụ với GCC:

```powershell
gcc -Wall -Wextra callback.c -o callback.exe
.\callback.exe
```

Ví dụ với MSVC (chạy trong **x64 Native Tools Command Prompt**):

```cmd
cl /W4 create_process.c /Fe:create_process.exe
create_process.exe
```

Các ví dụ độc lập; thay tên file tương ứng với bài lab muốn chạy.

## Tài liệu
Đọc phần lý thuyết, sơ đồ cơ chế và phân loại chi tiết tại: **[Các phương pháp Shellcode / Code Execution trên Windows](/Windows_Shellcode_Code_Execution.md)**

Lưu ý: **Code Execution ≠ Shellcode Execution ≠ Process Injection.** Process Injection chỉ là một nhóm trong các phương pháp thực thi mã trên Windows.
