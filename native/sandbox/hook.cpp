// Veyl.SandboxHook.dll: loaded into every sandboxed process (and its children).
//
// It patches a handful of ntdll system-call stubs so VEYL can:
//   * redirect file writes into the sandbox folder (copy-on-write), so the program
//     believes it changed your files while the real ones are untouched;
//   * record what the program tries to do: files, registry, child processes,
//     code injection, driver loads and network connections;
//   * block network connections and driver loads outright.
//
// This is the visibility layer. The hard boundary is the low-integrity, restricted
// token and job object the host (sandbox.cpp) starts the process with: even a program
// that strips these hooks can't write to your files, registry or other processes.
//
// Hooks: the first 12 bytes of each Nt* stub become `mov rax, hook; jmp rax`. The
// "real" function is a small trampoline that loads the syscall number and jumps to
// the stub's own `syscall` instruction, so the call still enters the kernel from ntdll.
//
// The same source builds Veyl.SandboxHook32.dll for 32-bit programs (WOW64). There each stub
// is `mov eax, ssn; mov edx, Wow64SystemServiceCall; call edx; ret n`, which doesn't depend
// on where it sits, so the trampoline is a plain copy and the stub starts with `jmp hook`.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "inject32.hpp"

namespace {

// ------------------------------------------------------------------ constants
constexpr NTSTATUS kSuccess = 0;
constexpr NTSTATUS kAccessDenied = (NTSTATUS)0xC0000022;
constexpr NTSTATUS kNotFound = (NTSTATUS)0xC0000034;
constexpr NTSTATUS kNameCollision = (NTSTATUS)0xC0000035;  // "already exists", from CreateDirectory on an existing folder

constexpr ULONG kSupersede = 0, kOpen = 1, kCreate = 2, kOpenIf = 3, kOverwrite = 4, kOverwriteIf = 5;
constexpr ULONG_PTR kInfoCreated = 2;
constexpr ULONG kDirectoryFile = 0x00000001;
constexpr ULONG kDeleteOnClose = 0x00001000;

constexpr ACCESS_MASK kFileWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE |
                                   WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
constexpr ACCESS_MASK kKeyWrite = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
constexpr ACCESS_MASK kProcInject = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

// ------------------------------------------------------------------ config + state
std::wstring g_root;   // Win32 path of this run's sandbox folder, no trailing slash
std::wstring g_rootLower;
std::wstring g_dll;    // our own path, for injecting into children
std::wstring g_dll32;  // the 32-bit monitor, for 32-bit children of a 64-bit program
bool g_blockNet = true;
bool g_active = false;
bool g_sandboxHasFiles = false;  // skip lookups for reads until anything has been redirected

HANDLE g_log = INVALID_HANDLE_VALUE;
SRWLOCK g_lock = SRWLOCK_INIT;  // guards the log, dedupe set and deleted set
std::unordered_set<std::wstring> g_seen;
std::unordered_set<std::wstring> g_deleted;  // lower-case Win32 paths deleted "inside" the sandbox
std::unordered_set<DWORD> g_children;        // processes we created; Windows itself writes into them after creation

struct DriveMap {
    std::wstring device;  // \Device\HarddiskVolume3
    wchar_t letter;
};
std::vector<DriveMap> g_drives;

thread_local int t_depth = 0;  // >0 while VEYL's own code runs, so our file ops aren't redirected or logged

struct Inside {
    bool first;
    Inside() : first(t_depth == 0) { ++t_depth; }
    ~Inside() { --t_depth; }
};

// ------------------------------------------------------------------ tiny helpers
std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

bool starts_with_i(const std::wstring& s, const std::wstring& prefix) {
    return s.size() >= prefix.size() && _wcsnicmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
}

std::wstring from_us(const UNICODE_STRING* us) {
    return us && us->Buffer ? std::wstring(us->Buffer, us->Length / sizeof(wchar_t)) : std::wstring();
}

std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

void json_str(std::string& out, const std::wstring& w) {
    out += '"';
    for (char c : utf8(w)) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    sprintf_s(buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

// One JSON object per line. `dedupe` = only log the first time this op+key appears.
void log_event(const char* op, std::initializer_list<std::pair<const char*, std::wstring>> fields, bool dedupe = true) {
    if (g_log == INVALID_HANDLE_VALUE) return;
    if (dedupe) {
        std::wstring key(op, op + strlen(op));
        for (auto& f : fields) key += L"|" + f.second;
        AcquireSRWLockExclusive(&g_lock);
        bool fresh = g_seen.insert(lower(key)).second;
        ReleaseSRWLockExclusive(&g_lock);
        if (!fresh) return;
    }
    std::string line = "{\"t\":" + std::to_string(GetTickCount64()) + ",\"pid\":" + std::to_string(GetCurrentProcessId()) +
                       ",\"op\":\"" + op + "\"";
    for (auto& f : fields) {
        line += ",\"";
        line += f.first;
        line += "\":";
        json_str(line, f.second);
    }
    line += "}\n";
    AcquireSRWLockExclusive(&g_lock);
    DWORD written;
    WriteFile(g_log, line.data(), (DWORD)line.size(), &written, nullptr);
    ReleaseSRWLockExclusive(&g_lock);
}

std::wstring status_text(NTSTATUS st) {
    if (st == kSuccess) return L"ok";
    if (st == kAccessDenied) return L"blocked";
    wchar_t buf[16];
    swprintf_s(buf, L"0x%08X", (unsigned)st);
    return buf;
}

// ------------------------------------------------------------------ names of handles
using NtQueryObject_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryKey_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
NtQueryObject_t pNtQueryObject;
NtQueryKey_t pNtQueryKey;

std::wstring handle_name(HANDLE h) {
    if (!h || !pNtQueryObject) return {};
    alignas(8) BYTE buf[2048];
    ULONG len = 0;
    if (pNtQueryObject(h, 1 /* ObjectNameInformation */, buf, sizeof buf, &len) != kSuccess) return {};
    return from_us(reinterpret_cast<UNICODE_STRING*>(buf));
}

std::wstring key_name(HANDLE h) {
    if (!h || !pNtQueryKey) return {};
    alignas(8) BYTE buf[2048];
    ULONG len = 0;
    if (pNtQueryKey(h, 3 /* KeyNameInformation */, buf, sizeof buf - 2, &len) != kSuccess) return {};
    ULONG n = *reinterpret_cast<ULONG*>(buf);
    return std::wstring(reinterpret_cast<wchar_t*>(buf + 4), n / sizeof(wchar_t));
}

// \REGISTRY\USER\S-1-5-21-...\Software -> HKCU\Software, \REGISTRY\MACHINE -> HKLM
std::wstring friendly_key(std::wstring k) {
    if (starts_with_i(k, L"\\REGISTRY\\MACHINE")) return L"HKLM" + k.substr(17);
    if (starts_with_i(k, L"\\REGISTRY\\USER\\")) {
        size_t sid_end = k.find(L'\\', 15);
        std::wstring sid = k.substr(15, sid_end == std::wstring::npos ? std::wstring::npos : sid_end - 15);
        std::wstring rest = sid_end == std::wstring::npos ? L"" : k.substr(sid_end);
        bool classes = sid.size() > 8 && _wcsicmp(sid.c_str() + sid.size() - 8, L"_Classes") == 0;
        return (classes ? L"HKCU\\Software\\Classes" : L"HKCU") + rest;
    }
    return k;
}

std::wstring key_path(POBJECT_ATTRIBUTES oa) {
    if (!oa) return {};
    std::wstring name = from_us(oa->ObjectName);
    if (!oa->RootDirectory) return friendly_key(name);
    std::wstring root = key_name(oa->RootDirectory);
    if (root.empty()) return name;
    return friendly_key(name.empty() ? root : root + L"\\" + name);
}

// ------------------------------------------------------------------ path mapping
// NT path -> "C:\..." or empty when it isn't a file on a local drive (pipes, devices...).
std::wstring to_win32(const std::wstring& nt) {
    auto drive_form = [](const std::wstring& rest) -> std::wstring {
        if (rest.size() >= 2 && iswalpha(rest[0]) && rest[1] == L':' && (rest.size() == 2 || rest[2] == L'\\')) return rest;
        return {};
    };
    if (starts_with_i(nt, L"\\??\\")) return drive_form(nt.substr(4));
    if (starts_with_i(nt, L"\\GLOBAL??\\")) return drive_form(nt.substr(10));
    if (starts_with_i(nt, L"\\Device\\")) {
        for (const auto& d : g_drives) {
            if (starts_with_i(nt, d.device) && (nt.size() == d.device.size() || nt[d.device.size()] == L'\\'))
                return std::wstring(1, d.letter) + L":" + nt.substr(d.device.size());
        }
    }
    return {};
}

// "C:\..." path of an open file or directory handle, or empty.
std::wstring file_handle_path(HANDLE h) {
    wchar_t buf[1024];
    DWORD n = GetFinalPathNameByHandleW(h, buf, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n > 0 && n < 1024) {
        std::wstring p(buf, n);
        if (starts_with_i(p, L"\\\\?\\") && p.size() > 6 && p[5] == L':') return p.substr(4);
    }
    return to_win32(handle_name(h));  // fallback: device-path table
}

std::wstring object_path(POBJECT_ATTRIBUTES oa) {
    if (!oa || !oa->ObjectName) return {};
    std::wstring name = from_us(oa->ObjectName);
    if (!oa->RootDirectory) return to_win32(name);
    std::wstring root = file_handle_path(oa->RootDirectory);
    if (root.empty()) return {};
    if (name.empty()) return root;
    if (root.back() != L'\\') root += L'\\';
    return root + name;
}

bool in_sandbox(const std::wstring& win) { return starts_with_i(win, g_root) && (win.size() == g_root.size() || win[g_root.size()] == L'\\'); }

// C:\Users\x\file.txt -> <root>\drive\C\Users\x\file.txt
std::wstring sandbox_path(const std::wstring& win) { return g_root + L"\\drive\\" + win.substr(0, 1) + win.substr(2); }

// The reverse: <root>\drive\C\Users\x -> C:\Users\x (empty if not a redirected path)
std::wstring original_path(const std::wstring& sbx) {
    std::wstring prefix = g_root + L"\\drive\\";
    if (!starts_with_i(sbx, prefix) || sbx.size() < prefix.size() + 1) return {};
    std::wstring rest = sbx.substr(prefix.size());
    return rest.substr(0, 1) + L":" + rest.substr(1);
}

bool exists(const std::wstring& win) { return GetFileAttributesW(win.c_str()) != INVALID_FILE_ATTRIBUTES; }
bool is_dir(const std::wstring& win) {
    DWORD a = GetFileAttributesW(win.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

void ensure_parent(const std::wstring& path) {
    for (size_t i = g_root.size() + 1; (i = path.find(L'\\', i)) != std::wstring::npos; ++i)
        CreateDirectoryW(path.substr(0, i).c_str(), nullptr);
}

bool is_deleted(const std::wstring& win) {
    AcquireSRWLockShared(&g_lock);
    bool d = g_deleted.count(lower(win)) > 0;
    ReleaseSRWLockShared(&g_lock);
    return d;
}

void set_deleted(const std::wstring& win, bool deleted) {
    AcquireSRWLockExclusive(&g_lock);
    if (deleted) g_deleted.insert(lower(win));
    else g_deleted.erase(lower(win));
    ReleaseSRWLockExclusive(&g_lock);
}

// A rewritten OBJECT_ATTRIBUTES pointing into the sandbox.
struct Redirect {
    bool active = false;
    std::wstring nt;
    UNICODE_STRING us{};
    OBJECT_ATTRIBUTES oa{};
    void to(POBJECT_ATTRIBUTES orig, const std::wstring& win) {
        nt = L"\\??\\" + win;
        us.Buffer = nt.data();
        us.Length = (USHORT)(nt.size() * sizeof(wchar_t));
        us.MaximumLength = us.Length;
        oa = *orig;
        oa.RootDirectory = nullptr;
        oa.ObjectName = &us;
        // Installers often lock their unpack folder to Administrators/SYSTEM. The sandbox token has
        // admin denied, so honouring that would lock the program out of its own sandboxed copy.
        oa.SecurityDescriptor = nullptr;
        active = true;
    }
};

enum class FileAction { Passthrough, Redirected, NotFound };

// Decides what to do with a file open/create. Copies the original into the sandbox
// the first time something wants to change it.
FileAction plan_file(POBJECT_ATTRIBUTES oa, ACCESS_MASK access, ULONG disposition, ULONG options, Redirect& r,
                     std::wstring& win, bool& write) {
    win = object_path(oa);
    write = false;
    if (win.empty() || in_sandbox(win)) return FileAction::Passthrough;

    bool deleted = !g_deleted.empty() && is_deleted(win);
    bool creates = disposition == kSupersede || disposition == kCreate || disposition == kOverwrite ||
                   disposition == kOverwriteIf || (disposition == kOpenIf && (deleted || !exists(win)));
    write = (access & kFileWrite) || creates;
    std::wstring sbx = sandbox_path(win);

    if (!write) {
        if (g_sandboxHasFiles && exists(sbx)) {
            r.to(oa, sbx);
            return FileAction::Redirected;
        }
        return deleted ? FileAction::NotFound : FileAction::Passthrough;
    }

    if (deleted && !creates) return FileAction::NotFound;
    if (!exists(sbx)) {
        ensure_parent(sbx);
        if (!deleted && exists(win)) {
            if (is_dir(win) || (options & kDirectoryFile)) CreateDirectoryW(sbx.c_str(), nullptr);
            else if (disposition != kSupersede && disposition != kOverwrite && disposition != kOverwriteIf)
                CopyFileW(win.c_str(), sbx.c_str(), TRUE);
        }
    }
    if (deleted) set_deleted(win, false);
    g_sandboxHasFiles = true;
    r.to(oa, sbx);
    return FileAction::Redirected;
}

// ------------------------------------------------------------------ hook plumbing
BYTE* g_stubs = nullptr;
size_t g_stubUsed = 0;

bool patch_code(BYTE* fn, const BYTE* patch, size_t n) {
    DWORD old;
    if (!VirtualProtect(fn, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(fn, patch, n);
    VirtualProtect(fn, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fn, n);
    return true;
}

#if defined(_M_IX86)
bool install(HMODULE ntdll, const char* name, void* hook, void** real) {
    BYTE* fn = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, name));
    // Expected WOW64 stub: B8 <ssn>  BA <Wow64SystemServiceCall>  FF D2  C2 <n> 00  (or C3)
    if (!fn || fn[0] != 0xB8 || fn[5] != 0xBA || fn[10] != 0xFF || fn[11] != 0xD2 || (fn[12] != 0xC2 && fn[12] != 0xC3)) {
        log_event("monitor.gap", {{"call", std::wstring(name, name + strlen(name))}});
        return false;
    }
    size_t len = fn[12] == 0xC2 ? 15 : 13;
    BYTE* t = g_stubs + g_stubUsed;
    g_stubUsed += 32;
    memcpy(t, fn, len);
    *real = t;

    BYTE patch[5] = {0xE9};  // jmp rel32
    LONG rel = (LONG)((BYTE*)hook - (fn + 5));
    memcpy(patch + 1, &rel, 4);
    return patch_code(fn, patch, sizeof patch);
}
#else
bool install(HMODULE ntdll, const char* name, void* hook, void** real) {
    BYTE* fn = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, name));
    // Expected x64 stub: 4C 8B D1  B8 <ssn>  F6 04 25 08 03 FE 7F 01  75 03  0F 05  C3
    if (!fn || fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1 || fn[3] != 0xB8 || fn[18] != 0x0F || fn[19] != 0x05) {
        log_event("monitor.gap", {{"call", std::wstring(name, name + strlen(name))}});
        return false;
    }
    DWORD ssn = *reinterpret_cast<DWORD*>(fn + 4);
    BYTE* t = g_stubs + g_stubUsed;
    g_stubUsed += 32;
    // mov r10, rcx ; mov eax, ssn ; mov r11, &fn[18] ; jmp r11   (r11 is clobbered by syscall anyway)
    BYTE code[] = {0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xFF, 0xE3};
    memcpy(code + 4, &ssn, 4);
    void* syscall_at = fn + 18;
    memcpy(code + 10, &syscall_at, 8);
    memcpy(t, code, sizeof code);
    *real = t;

    BYTE patch[12] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};  // mov rax, hook ; jmp rax
    memcpy(patch + 2, &hook, 8);
    return patch_code(fn, patch, sizeof patch);
}
#endif

#define REAL(name) name##_t real_##name = nullptr

// ------------------------------------------------------------------ child processes
// Puts the monitor into a freshly created (suspended) child. A 64-bit child gets this DLL
// through an APC on its first thread; a 32-bit child gets the 32-bit monitor through its
// import table (see inject32.hpp). The 32-bit monitor can't reach into a 64-bit child.
bool inject(HANDLE process, HANDLE thread) {
    BOOL wow64 = FALSE;
    IsWow64Process(process, &wow64);
#if defined(_M_IX86)
    (void)thread;
    return wow64 && veyl_inject::add_import32(process, g_dll);
#else
    if (wow64) return !g_dll32.empty() && veyl_inject::add_import32(process, g_dll32);
    size_t bytes = (g_dll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote || !WriteProcessMemory(process, remote, g_dll.c_str(), bytes, nullptr)) return false;
    auto load = reinterpret_cast<PAPCFUNC>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    return QueueUserAPC(load, thread, reinterpret_cast<ULONG_PTR>(remote)) != 0;
#endif
}

// ------------------------------------------------------------------ hooks
using NtCreateFile_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG,
                                        ULONG, ULONG, ULONG, PVOID, ULONG);
using NtOpenFile_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
using NtDeleteFile_t = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES);
using NtSetInformationFile_t = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
using NtCreateKey_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
using NtOpenKey_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtOpenKeyEx_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
using NtSetValueKey_t = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
using NtDeleteKey_t = NTSTATUS(NTAPI*)(HANDLE);
using NtDeleteValueKey_t = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING);
using NtCreateUserProcess_t = NTSTATUS(NTAPI*)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                               POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID, PVOID, PVOID);
using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T,
                                            SIZE_T, SIZE_T, PVOID);
using NtQueueApcThread_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID);
using NtOpenProcess_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
using NtLoadDriver_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using NtDeviceIoControlFile_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

REAL(NtCreateFile);
REAL(NtOpenFile);
REAL(NtDeleteFile);
REAL(NtSetInformationFile);
REAL(NtCreateKey);
REAL(NtOpenKey);
REAL(NtOpenKeyEx);
REAL(NtSetValueKey);
REAL(NtDeleteKey);
REAL(NtDeleteValueKey);
REAL(NtCreateUserProcess);
REAL(NtWriteVirtualMemory);
REAL(NtCreateThreadEx);
REAL(NtQueueApcThread);
REAL(NtOpenProcess);
REAL(NtLoadDriver);
REAL(NtDeviceIoControlFile);

void after_open(const std::wstring& win, NTSTATUS st, PIO_STATUS_BLOCK iosb, bool redirected, bool write, ULONG options) {
    if (!write || st == kNameCollision) return;  // a failed create of something that exists changes nothing
    std::wstring result = redirected && st == kSuccess ? L"sandboxed" : status_text(st);
    // DeleteFileW opens with delete-on-close: the sandboxed copy goes when the handle
    // closes, and the original must vanish from the program's view.
    if ((options & kDeleteOnClose) && st == kSuccess && redirected) {
        set_deleted(win, true);
        log_event("file.delete", {{"path", win}, {"result", result}});
        return;
    }
    const char* op = st == kSuccess && iosb && iosb->Information == kInfoCreated ? "file.create" : "file.write";
    log_event(op, {{"path", win}, {"result", result}});
}

// File attribute queries never open the file, so they need their own redirect:
// otherwise the program would still "see" files it deleted and miss ones it created.
using NtQueryAttributesFile_t = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, PVOID);
NtQueryAttributesFile_t real_NtQueryAttributesFile = nullptr;
NtQueryAttributesFile_t real_NtQueryFullAttributesFile = nullptr;

NTSTATUS query_attributes(NtQueryAttributesFile_t real, POBJECT_ATTRIBUTES oa, PVOID info) {
    Inside in;
    if (!in.first || (!g_sandboxHasFiles && g_deleted.empty())) return real(oa, info);
    std::wstring win = object_path(oa);
    if (win.empty() || in_sandbox(win)) return real(oa, info);
    std::wstring sbx = sandbox_path(win);
    if (g_sandboxHasFiles && exists(sbx)) {
        Redirect r;
        r.to(oa, sbx);
        return real(&r.oa, info);
    }
    if (!g_deleted.empty() && is_deleted(win)) return kNotFound;
    return real(oa, info);
}

NTSTATUS NTAPI hk_NtQueryAttributesFile(POBJECT_ATTRIBUTES oa, PVOID info) {
    return query_attributes(real_NtQueryAttributesFile, oa, info);
}

NTSTATUS NTAPI hk_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES oa, PVOID info) {
    return query_attributes(real_NtQueryFullAttributesFile, oa, info);
}

NTSTATUS NTAPI hk_NtCreateFile(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb,
                               PLARGE_INTEGER alloc, ULONG attrs, ULONG share, ULONG disp, ULONG options, PVOID ea,
                               ULONG ealen) {
    Inside in;
    if (!in.first) return real_NtCreateFile(h, access, oa, iosb, alloc, attrs, share, disp, options, ea, ealen);
    Redirect r;
    std::wstring win;
    bool write;
    FileAction a = plan_file(oa, access, disp, options, r, win, write);
    if (a == FileAction::NotFound) return kNotFound;
    NTSTATUS st = real_NtCreateFile(h, access, r.active ? &r.oa : oa, iosb, alloc, attrs, share, disp, options, ea, ealen);
    after_open(win, st, iosb, r.active, write, options);
    return st;
}

NTSTATUS NTAPI hk_NtOpenFile(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb, ULONG share,
                             ULONG options) {
    Inside in;
    if (!in.first) return real_NtOpenFile(h, access, oa, iosb, share, options);
    Redirect r;
    std::wstring win;
    bool write;
    FileAction a = plan_file(oa, access, kOpen, options, r, win, write);
    if (a == FileAction::NotFound) return kNotFound;
    NTSTATUS st = real_NtOpenFile(h, access, r.active ? &r.oa : oa, iosb, share, options);
    after_open(win, st, iosb, r.active, write, options);
    return st;
}

NTSTATUS NTAPI hk_NtDeleteFile(POBJECT_ATTRIBUTES oa) {
    Inside in;
    if (!in.first) return real_NtDeleteFile(oa);
    std::wstring win = object_path(oa);
    if (win.empty() || in_sandbox(win)) return real_NtDeleteFile(oa);
    std::wstring sbx = sandbox_path(win);
    if (exists(sbx)) DeleteFileW(sbx.c_str());
    set_deleted(win, true);  // the real file stays; the program just can't see it any more
    log_event("file.delete", {{"path", win}, {"result", L"sandboxed"}});
    return kSuccess;
}

// FILE_RENAME_INFORMATION, laid out by the compiler so it's right for both pointer sizes.
struct RenameInfo {
    union {
        BOOLEAN ReplaceIfExists;
        ULONG Flags;
    };
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
};
constexpr size_t kRenameName = offsetof(RenameInfo, FileName);

NTSTATUS NTAPI hk_NtSetInformationFile(HANDLE h, PIO_STATUS_BLOCK iosb, PVOID info, ULONG len, ULONG cls) {
    Inside in;
    if (!in.first) return real_NtSetInformationFile(h, iosb, info, len, cls);

    bool del = (cls == 13 && len >= 1 && *(BOOLEAN*)info) || (cls == 64 && len >= 4 && (*(ULONG*)info & 1));
    bool rename = (cls == 10 || cls == 65) && len >= kRenameName;
    if (!del && !rename) return real_NtSetInformationFile(h, iosb, info, len, cls);

    std::wstring self = file_handle_path(h);
    std::wstring orig = in_sandbox(self) ? original_path(self) : self;

    if (del) {
        NTSTATUS st = real_NtSetInformationFile(h, iosb, info, len, cls);
        if (st == kSuccess && !orig.empty()) set_deleted(orig, true);
        if (!orig.empty()) log_event("file.delete", {{"path", orig}, {"result", in_sandbox(self) ? L"sandboxed" : status_text(st)}});
        return st;
    }

    auto* ri = (RenameInfo*)info;
    HANDLE root = ri->RootDirectory;
    ULONG nameLen = ri->FileNameLength;
    if (kRenameName + (size_t)nameLen > len) return real_NtSetInformationFile(h, iosb, info, len, cls);
    std::wstring target(ri->FileName, nameLen / sizeof(wchar_t));
    std::wstring targetWin = root ? file_handle_path(root) + L"\\" + target : to_win32(target);
    if (targetWin.empty() || in_sandbox(targetWin)) return real_NtSetInformationFile(h, iosb, info, len, cls);

    // Point the rename at the sandboxed copy of the destination.
    std::wstring nt = L"\\??\\" + sandbox_path(targetWin);
    ensure_parent(sandbox_path(targetWin));
    std::vector<BYTE> buf(kRenameName + nt.size() * sizeof(wchar_t));
    auto* out = (RenameInfo*)buf.data();
    out->Flags = ri->Flags;
    out->RootDirectory = nullptr;
    out->FileNameLength = (ULONG)(nt.size() * sizeof(wchar_t));
    memcpy(out->FileName, nt.data(), nt.size() * sizeof(wchar_t));
    NTSTATUS st = real_NtSetInformationFile(h, iosb, buf.data(), (ULONG)buf.size(), cls);
    if (st == kSuccess) {
        if (!orig.empty()) set_deleted(orig, true);
        set_deleted(targetWin, false);
        g_sandboxHasFiles = true;
    }
    log_event("file.rename", {{"path", orig}, {"to", targetWin}, {"result", st == kSuccess ? L"sandboxed" : status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtCreateKey(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, ULONG ti, PUNICODE_STRING cls,
                              ULONG options, PULONG disposition) {
    Inside in;
    NTSTATUS st = real_NtCreateKey(h, access, oa, ti, cls, options, disposition);
    if (in.first && (access & kKeyWrite) && st != kNotFound) log_event("reg.write", {{"key", key_path(oa)}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtOpenKey(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa) {
    Inside in;
    NTSTATUS st = real_NtOpenKey(h, access, oa);
    if (in.first && (access & kKeyWrite) && st != kNotFound) log_event("reg.write", {{"key", key_path(oa)}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtOpenKeyEx(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, ULONG options) {
    Inside in;
    NTSTATUS st = real_NtOpenKeyEx(h, access, oa, options);
    if (in.first && (access & kKeyWrite) && st != kNotFound) log_event("reg.write", {{"key", key_path(oa)}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtSetValueKey(HANDLE h, PUNICODE_STRING name, ULONG ti, ULONG type, PVOID data, ULONG size) {
    Inside in;
    NTSTATUS st = real_NtSetValueKey(h, name, ti, type, data, size);
    if (in.first) {
        std::wstring preview;
        if ((type == REG_SZ || type == REG_EXPAND_SZ) && data)
            preview.assign((wchar_t*)data, std::min<size_t>(size / sizeof(wchar_t), 260));
        else if (type == REG_DWORD && data && size >= 4)
            preview = std::to_wstring(*(DWORD*)data);
        while (!preview.empty() && preview.back() == 0) preview.pop_back();
        log_event("reg.setvalue", {{"key", friendly_key(key_name(h))}, {"value", from_us(name)}, {"data", preview},
                                   {"result", status_text(st)}});
    }
    return st;
}

NTSTATUS NTAPI hk_NtDeleteKey(HANDLE h) {
    Inside in;
    std::wstring k = in.first ? friendly_key(key_name(h)) : L"";
    NTSTATUS st = real_NtDeleteKey(h);
    if (in.first) log_event("reg.delete", {{"key", k}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtDeleteValueKey(HANDLE h, PUNICODE_STRING name) {
    Inside in;
    NTSTATUS st = real_NtDeleteValueKey(h, name);
    if (in.first) log_event("reg.delete", {{"key", friendly_key(key_name(h))}, {"value", from_us(name)}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtCreateUserProcess(PHANDLE ph, PHANDLE th, ACCESS_MASK pa, ACCESS_MASK ta, POBJECT_ATTRIBUTES poa,
                                      POBJECT_ATTRIBUTES toa, ULONG pflags, ULONG tflags, PVOID params, PVOID info,
                                      PVOID attrs) {
    Inside in;
    if (!in.first) return real_NtCreateUserProcess(ph, th, pa, ta, poa, toa, pflags, tflags, params, info, attrs);
    std::wstring image, cmdline;
    if (params) {
        auto* pp = static_cast<RTL_USER_PROCESS_PARAMETERS*>(params);
        image = from_us(&pp->ImagePathName);
        cmdline = from_us(&pp->CommandLine);
    }
    const ULONG kSuspended = 0x1;
    NTSTATUS st = real_NtCreateUserProcess(ph, th, pa, ta, poa, toa, pflags, tflags | kSuspended, params, info, attrs);
    std::wstring monitored = L"no";
    if (st == kSuccess) {
        DWORD child = GetProcessId(*ph);
        AcquireSRWLockExclusive(&g_lock);
        g_children.insert(child);
        ReleaseSRWLockExclusive(&g_lock);
        if (inject(*ph, *th)) monitored = L"yes";
        if (!(tflags & kSuspended)) ResumeThread(*th);
    }
    log_event("proc.create", {{"image", image}, {"cmdline", cmdline}, {"monitored", monitored}, {"result", status_text(st)}}, false);
    return st;
}

bool other_process(HANDLE process) {
    DWORD pid = GetProcessId(process);
    return pid != 0 && pid != GetCurrentProcessId();
}

bool is_child(HANDLE process) {
    DWORD pid = GetProcessId(process);
    AcquireSRWLockShared(&g_lock);
    bool child = g_children.count(pid) > 0;
    ReleaseSRWLockShared(&g_lock);
    return child;
}

NTSTATUS NTAPI hk_NtWriteVirtualMemory(HANDLE process, PVOID base, PVOID buf, SIZE_T size, PSIZE_T written) {
    Inside in;
    NTSTATUS st = real_NtWriteVirtualMemory(process, base, buf, size, written);
    // Plain writes into our own children are normal (CreateProcess does it); remote
    // threads or APCs into them are still reported, which is how hollowing shows up.
    if (in.first && other_process(process) && !is_child(process))
        log_event("inject.write", {{"target", std::to_wstring(GetProcessId(process))}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtCreateThreadEx(PHANDLE th, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, HANDLE process, PVOID start, PVOID arg,
                                   ULONG flags, SIZE_T zero, SIZE_T stack, SIZE_T maxstack, PVOID attrs) {
    Inside in;
    NTSTATUS st = real_NtCreateThreadEx(th, a, oa, process, start, arg, flags, zero, stack, maxstack, attrs);
    if (in.first && other_process(process))
        log_event("inject.thread", {{"target", std::to_wstring(GetProcessId(process))}, {"result", status_text(st)}});
    return st;
}

NTSTATUS NTAPI hk_NtQueueApcThread(HANDLE thread, PVOID routine, PVOID a1, PVOID a2, PVOID a3) {
    Inside in;
    NTSTATUS st = real_NtQueueApcThread(thread, routine, a1, a2, a3);
    if (in.first) {
        DWORD pid = GetProcessIdOfThread(thread);
        if (pid && pid != GetCurrentProcessId())
            log_event("inject.apc", {{"target", std::to_wstring(pid)}, {"result", status_text(st)}});
    }
    return st;
}

NTSTATUS NTAPI hk_NtOpenProcess(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid) {
    Inside in;
    NTSTATUS st = real_NtOpenProcess(h, access, oa, cid);
    if (in.first && cid && (access & (kProcInject | PROCESS_VM_READ))) {
        DWORD pid = (DWORD)(ULONG_PTR)cid->UniqueProcess;
        if (pid != GetCurrentProcessId())
            log_event("proc.open", {{"target", std::to_wstring(pid)}, {"access", (access & kProcInject) ? L"write" : L"read"},
                                    {"result", status_text(st)}});
    }
    return st;
}

NTSTATUS NTAPI hk_NtLoadDriver(PUNICODE_STRING service) {
    Inside in;
    log_event("driver.load", {{"service", from_us(service)}, {"result", L"blocked"}});
    return kAccessDenied;
}

// AFD (Winsock's kernel driver) connect requests. The address layout isn't documented,
// so find the first plausible IPv4/IPv6 sockaddr in the request buffer. Writes into a
// plain buffer (no C++ objects) so the caller can wrap it in __try.
bool find_address(const BYTE* p, ULONG len, wchar_t* out, size_t cap, bool* loopback) {
    *loopback = false;
    for (ULONG off = 0; off + 8 <= len && off < 96; off += 2) {
        USHORT family = *(const USHORT*)(p + off);
        USHORT port = (USHORT)((p[off + 2] << 8) | p[off + 3]);
        if (family == 2 /* AF_INET */ && port) {
            const BYTE* a = p + off + 4;
            if (!a[0] && !a[1] && !a[2] && !a[3]) continue;
            *loopback = a[0] == 127;
            swprintf_s(out, cap, L"%u.%u.%u.%u:%u", a[0], a[1], a[2], a[3], port);
            return true;
        }
        if (family == 23 /* AF_INET6 */ && port && off + 24 <= len) {
            const BYTE* a = p + off + 8;
            bool zero = true, lo = true;
            for (int i = 0; i < 16; ++i) zero &= a[i] == 0;
            if (zero) continue;
            for (int i = 0; i < 15; ++i) lo &= a[i] == 0;
            *loopback = lo && a[15] == 1;
            swprintf_s(out, cap, L"[%x:%x:%x:%x:%x:%x:%x:%x]:%u", (a[0] << 8) | a[1], (a[2] << 8) | a[3], (a[4] << 8) | a[5],
                       (a[6] << 8) | a[7], (a[8] << 8) | a[9], (a[10] << 8) | a[11], (a[12] << 8) | a[13],
                       (a[14] << 8) | a[15], port);
            return true;
        }
    }
    return false;
}

bool safe_find_address(const void* p, ULONG len, wchar_t* out, size_t cap, bool* loopback) {
    __try {
        return find_address((const BYTE*)p, len, out, cap, loopback);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

NTSTATUS NTAPI hk_NtDeviceIoControlFile(HANDLE f, HANDLE ev, PVOID apc, PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG code,
                                        PVOID in_buf, ULONG in_len, PVOID out_buf, ULONG out_len) {
    const ULONG kAfdConnect = 0x12007, kAfdSuperConnect = 0x120C7;
    if ((code == kAfdConnect || code == kAfdSuperConnect) && in_buf && t_depth == 0) {
        Inside in;
        bool loopback = false;
        wchar_t buf[64] = {};
        std::wstring addr = safe_find_address(in_buf, in_len, buf, 64, &loopback) ? buf : L"";
        bool block = g_blockNet && !loopback;
        log_event("net.connect", {{"address", addr.empty() ? L"(unknown)" : addr}, {"result", block ? L"blocked" : L"allowed"}});
        if (block) return kAccessDenied;
    }
    return real_NtDeviceIoControlFile(f, ev, apc, ctx, iosb, code, in_buf, in_len, out_buf, out_len);
}

// ------------------------------------------------------------------ start-up
std::wstring env(const wchar_t* name) {
    wchar_t buf[1024];
    DWORD n = GetEnvironmentVariableW(name, buf, 1024);
    return n && n < 1024 ? std::wstring(buf, n) : std::wstring();
}

void init(HMODULE self) {
    g_root = env(L"VEYL_SANDBOX_ROOT");
    if (g_root.empty()) return;  // loaded outside a sandbox: do nothing
    while (!g_root.empty() && g_root.back() == L'\\') g_root.pop_back();
    g_rootLower = lower(g_root);
    g_blockNet = env(L"VEYL_SANDBOX_NET") != L"allow";

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(self, path, MAX_PATH);
    g_dll = path;
#if !defined(_M_IX86)
    std::wstring dll32 = g_dll.substr(0, g_dll.find_last_of(L'\\') + 1) + L"Veyl.SandboxHook32.dll";
    if (GetFileAttributesW(dll32.c_str()) != INVALID_FILE_ATTRIBUTES) g_dll32 = dll32;
#endif

    for (wchar_t d = L'A'; d <= L'Z'; ++d) {
        wchar_t drive[3] = {d, L':', 0}, target[512];
        if (QueryDosDeviceW(drive, target, 512)) g_drives.push_back({target, d});
    }
    g_sandboxHasFiles = GetFileAttributesW((g_root + L"\\drive").c_str()) != INVALID_FILE_ATTRIBUTES;

    g_log = CreateFileW((g_root + L"\\events.jsonl").c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    pNtQueryObject = (NtQueryObject_t)GetProcAddress(nt, "NtQueryObject");
    pNtQueryKey = (NtQueryKey_t)GetProcAddress(nt, "NtQueryKey");

    g_stubs = (BYTE*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_stubs) return;
#define HOOK(name) install(nt, #name, (void*)hk_##name, (void**)&real_##name)
    HOOK(NtCreateFile);
    HOOK(NtOpenFile);
    HOOK(NtDeleteFile);
    HOOK(NtSetInformationFile);
    HOOK(NtCreateKey);
    HOOK(NtOpenKey);
    HOOK(NtOpenKeyEx);
    HOOK(NtSetValueKey);
    HOOK(NtDeleteKey);
    HOOK(NtDeleteValueKey);
    HOOK(NtCreateUserProcess);
    HOOK(NtWriteVirtualMemory);
    HOOK(NtCreateThreadEx);
    HOOK(NtQueueApcThread);
    HOOK(NtOpenProcess);
    HOOK(NtLoadDriver);
    HOOK(NtDeviceIoControlFile);
    HOOK(NtQueryAttributesFile);
    HOOK(NtQueryFullAttributesFile);
#undef HOOK
    DWORD old;
    VirtualProtect(g_stubs, 4096, PAGE_EXECUTE_READ, &old);
    g_active = true;

    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    log_event("proc.start", {{"image", exe}, {"cmdline", GetCommandLineW()}}, false);
}

}  // namespace

// The 32-bit monitor is loaded through the program's import table, which needs an export
// to import. It does nothing; DllMain does the work.
extern "C" __declspec(dllexport) void VeylHook() {}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        Inside in;  // our own set-up I/O must not be redirected
        init(module);
    }
    return TRUE;
}
