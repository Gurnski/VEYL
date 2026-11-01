// Behaves like a (harmless) piece of malware, so the sandbox tests can check that each
// action is contained and recorded. Exit code: 0 if every action behaved as it should
// inside the sandbox, otherwise a bitmask of the ones that didn't.
//   Veyl.SandboxProbe.exe <new-file> <existing-file> <file-to-delete>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <string>

#pragma comment(lib, "ws2_32.lib")

static std::string read_all(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "<missing>";
    char buf[256];
    DWORD got = 0;
    ReadFile(h, buf, sizeof buf, &got, nullptr);
    CloseHandle(h);
    return std::string(buf, got);
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 4) return 0xFF;
    int fails = 0;

    // 1. Create a new file and read it back: the program must see its own write.
    HANDLE h = CreateFileW(argv[1], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    DWORD n;
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, "probe-new", 9, &n, nullptr);
        CloseHandle(h);
    }
    if (read_all(argv[1]) != "probe-new") fails |= 0x01;

    // 2. Append to an existing file; the program sees the change.
    h = CreateFileW(argv[2], FILE_APPEND_DATA, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, " modified", 9, &n, nullptr);
        CloseHandle(h);
    }
    if (read_all(argv[2]) != "original modified") fails |= 0x02;

    // 3. Delete a file; to the program it's gone.
    DeleteFileW(argv[3]);
    if (GetFileAttributesW(argv[3]) != INVALID_FILE_ATTRIBUTES) fails |= 0x04;

    // 4. Persistence attempt: should be refused.
    HKEY run;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &run) ==
        ERROR_SUCCESS) {
        const wchar_t* v = L"C:\\probe.exe";
        if (RegSetValueExW(run, L"VEYLProbe", 0, REG_SZ, (const BYTE*)v, (DWORD)(wcslen(v) + 1) * 2) == ERROR_SUCCESS) {
            RegDeleteValueW(run, L"VEYLProbe");
            fails |= 0x08;
        }
        RegCloseKey(run);
    }

    // 5. Child process: should run (and be sandboxed too).
    STARTUPINFOW si{sizeof si};
    PROCESS_INFORMATION pi{};
    wchar_t cmd[] = L"cmd.exe /c exit 7";
    DWORD code = 0;
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if (code != 7) fails |= 0x10;

    // 6. Network: should be blocked.
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof addr) == 0) fails |= 0x20;
    closesocket(s);
    WSACleanup();

    // 7. Clipboard: reading it should be refused by the job.
    if (OpenClipboard(nullptr)) {
        if (GetClipboardData(CF_UNICODETEXT)) fails |= 0x40;
        CloseClipboard();
    }
    return fails;
}
