// Runs Veyl.SandboxProbe.exe inside the sandbox and checks that nothing reached the
// real system and that every action was recorded. Exit code 0 = passed.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "veyl_core.h"

#pragma comment(lib, "shell32.lib")

static int failures = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                 \
        }                                                               \
    } while (0)

static std::wstring exe_dir() {
    wchar_t p[MAX_PATH];
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring s(p);
    return s.substr(0, s.find_last_of(L'\\'));
}

static std::string read_text(const std::wstring& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

static void write_text(const std::wstring& path, const std::string& s) {
    std::ofstream(path, std::ios::binary) << s;
}

static void remove_tree(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            std::wstring p = dir + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(p);
            else DeleteFileW(p.c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

// Runs one probe (64-bit or 32-bit) through the sandbox and checks the results.
static void run_probe(const std::wstring& bin, const wchar_t* probe) {
    std::printf("== %ls\n", probe);
    int before = failures;
    wchar_t* lowAppData = nullptr;
    SHGetKnownFolderPath(FOLDERID_LocalAppDataLow, 0, nullptr, &lowAppData);
    std::wstring root = std::wstring(lowAppData) + L"\\VEYL\\Sandbox\\test-" + std::to_wstring(GetCurrentProcessId());
    CoTaskMemFree(lowAppData);
    SHCreateDirectoryExW(nullptr, root.substr(0, root.find_last_of(L'\\')).c_str(), nullptr);

    // Real files in the user's Documents that the probe will "attack".
    wchar_t* docs = nullptr;
    SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs);
    std::wstring d(docs);
    CoTaskMemFree(docs);
    std::wstring tag = std::to_wstring(GetCurrentProcessId());
    std::wstring fresh = d + L"\\veyl-probe-new-" + tag + L".txt";
    std::wstring existing = d + L"\\veyl-probe-existing-" + tag + L".txt";
    std::wstring victim = d + L"\\veyl-probe-delete-" + tag + L".txt";
    write_text(existing, "original");
    write_text(victim, "please keep me");

    std::wstring args = L"\"" + fresh + L"\" \"" + existing + L"\" \"" + victim + L"\"";
    VeylSandbox* sb = nullptr;
    int pid = 0, monitored = 0;
    int rc = veyl_sandbox_start((bin + L"\\" + probe).c_str(), args.c_str(), root.c_str(),
                                (bin + L"\\Veyl.SandboxHook.dll").c_str(), 0, &sb, &pid, &monitored);
    CHECK(rc == VEYL_OK);
    CHECK(monitored == 1);
    if (rc != VEYL_OK) return;

    int active = 1, total = 0, code = -1;
    for (int i = 0; i < 300 && active > 0; ++i) {
        Sleep(100);
        veyl_sandbox_status(sb, &active, &total, &code);
    }
    std::printf("probe exit 0x%02X, %d process(es) in the job\n", code, total);
    CHECK(active == 0);
    CHECK(code == 0);      // every action behaved as expected from inside
    CHECK(total >= 2);     // the probe and its cmd.exe child were both in the job
    veyl_sandbox_close(sb);

    // Nothing reached the real files...
    CHECK(GetFileAttributesW(fresh.c_str()) == INVALID_FILE_ATTRIBUTES);
    CHECK(read_text(existing) == "original");
    CHECK(read_text(victim) == "please keep me");
    // ...the writes landed in the sandbox instead...
    std::wstring sbx = root + L"\\drive\\" + fresh.substr(0, 1) + fresh.substr(2);
    CHECK(read_text(sbx) == "probe-new");
    std::wstring sbx2 = root + L"\\drive\\" + existing.substr(0, 1) + existing.substr(2);
    CHECK(read_text(sbx2) == "original modified");
    // ...and the Run key is untouched.
    HKEY run;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &run) == ERROR_SUCCESS) {
        CHECK(RegQueryValueExW(run, L"VEYLProbe", nullptr, nullptr, nullptr, nullptr) == ERROR_FILE_NOT_FOUND);
        RegCloseKey(run);
    }

    // Every action was recorded.
    std::string log = read_text(root + L"\\events.jsonl");
    auto has = [&](const char* s) { return log.find(s) != std::string::npos; };
    CHECK(has("\"op\":\"proc.start\""));
    CHECK(has("\"op\":\"file.create\""));
    CHECK(has("\"op\":\"file.write\""));
    CHECK(has("\"op\":\"file.delete\""));
    CHECK(has("CurrentVersion\\\\Run") && has("\"result\":\"blocked\""));
    CHECK(has("\"op\":\"proc.create\"") && has("cmd.exe /c exit 7"));
    // Both children were monitored: the cmd.exe of the probe's own kind, and the 32-bit one.
    size_t monitored_children = 0;
    for (size_t at = 0; (at = log.find("\"monitored\":\"yes\"", at)) != std::string::npos; ++at) ++monitored_children;
    CHECK(monitored_children >= 2);
    // ...and the 32-bit one reported in from inside (proc.start comes from the monitor in that process).
    std::string lower_log = log;
    for (auto& c : lower_log) c = (char)tolower((unsigned char)c);
    CHECK(lower_log.find("\\\\syswow64\\\\cmd.exe /c exit 8") != std::string::npos);
    CHECK(lower_log.find("\"op\":\"proc.start\",\"image\":\"c:\\\\windows\\\\syswow64\\\\cmd.exe\"") != std::string::npos);
    CHECK(has("\"op\":\"net.connect\"") && has("1.1.1.1:443"));
    CHECK(!has("\"op\":\"monitor.gap\""));  // every hook went in
    if (failures > before) std::printf("---- events.jsonl ----\n%s\n", log.c_str());

    DeleteFileW(existing.c_str());
    DeleteFileW(victim.c_str());
    remove_tree(root);
}

int main() {
    std::wstring bin = exe_dir();
    run_probe(bin, L"Veyl.SandboxProbe.exe");
    // 32-bit: the probe runs under WOW64 with Veyl.SandboxHook32.dll, and its cmd.exe child
    // is the 32-bit one from SysWOW64, so this also covers 32-bit to 32-bit child injection.
    if (GetFileAttributesW((bin + L"\\Veyl.SandboxProbe32.exe").c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::printf("FAIL Veyl.SandboxProbe32.exe is missing (build.ps1 copies it from native\\build32)\n");
        ++failures;
    } else {
        run_probe(bin, L"Veyl.SandboxProbe32.exe");
    }
    std::printf(failures ? "%d FAILURE(S)\n" : "SANDBOX TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
