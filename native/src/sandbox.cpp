// Starts a program inside the VEYL sandbox.
//
// Isolation, enforced by Windows itself:
//   * a restricted token: Administrators is deny-only, privileges are stripped, and the
//     integrity level is Low. Low-integrity processes can't write to your files, the
//     registry outside AppDataLow, or any normal process, whatever they try;
//   * a job object: the whole process tree dies when VEYL closes the sandbox, process
//     count and memory are capped, and the clipboard, other windows, display settings
//     and shutdown are off limits.
// Visibility: Veyl.SandboxHook.dll is queued into the first thread before it runs, and
// passes itself on to child processes (see sandbox/hook.cpp). 32-bit programs get
// Veyl.SandboxHook32.dll through their import table instead (sandbox/inject32.hpp).
#include "common.hpp"

#include <aclapi.h>
#include <sddl.h>

#include "../sandbox/inject32.hpp"

#pragma comment(lib, "advapi32.lib")

struct VeylSandbox {
    HANDLE job = nullptr;
    HANDLE process = nullptr;
    DWORD pid = 0;
    ~VeylSandbox() {
        if (process) CloseHandle(process);
        if (job) CloseHandle(job);  // KILL_ON_JOB_CLOSE ends the whole tree
    }
};

namespace veyl {
namespace {

struct Handle {
    HANDLE h = nullptr;
    ~Handle() {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};

// An elevated token's default owner and default DACL for new objects are the
// Administrators group. With Administrators made deny-only, the program couldn't
// open its own process and thread objects and would die starting up
// (STATUS_DLL_INIT_FAILED). Point both at the user instead, as a normal token does.
bool own_objects_as_user(HANDLE token) {
    BYTE user_buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD len = 0;
    if (!GetTokenInformation(token, TokenUser, user_buf, sizeof user_buf, &len)) return false;
    PSID user = reinterpret_cast<TOKEN_USER*>(user_buf)->User.Sid;

    BYTE system_buf[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof system_buf;
    CreateWellKnownSid(WinLocalSystemSid, nullptr, system_buf, &size);

    DWORD acl_size = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(user) + GetLengthSid(system_buf);
    std::vector<BYTE> acl_buf(acl_size);
    PACL acl = reinterpret_cast<PACL>(acl_buf.data());
    if (!InitializeAcl(acl, acl_size, ACL_REVISION) || !AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, user) ||
        !AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, system_buf))
        return false;

    TOKEN_DEFAULT_DACL dacl{acl};
    TOKEN_OWNER owner{user};
    return SetTokenInformation(token, TokenDefaultDacl, &dacl, sizeof dacl) &&
           SetTokenInformation(token, TokenOwner, &owner, sizeof owner);
}

// Low-integrity, de-administrated copy of our own token.
HANDLE make_token() {
    Handle self;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &self.h))
        return nullptr;

    BYTE admins_buf[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof admins_buf;
    CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins_buf, &size);
    SID_AND_ATTRIBUTES deny{admins_buf, 0};

    HANDLE restricted = nullptr;
    if (!CreateRestrictedToken(self.h, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, &deny, 0, nullptr, 0, nullptr, &restricted))
        return nullptr;

    BYTE low_buf[SECURITY_MAX_SID_SIZE];
    size = sizeof low_buf;
    CreateWellKnownSid(WinLowLabelSid, nullptr, low_buf, &size);
    TOKEN_MANDATORY_LABEL label{{low_buf, SE_GROUP_INTEGRITY}};
    if (!SetTokenInformation(restricted, TokenIntegrityLevel, &label, sizeof label + GetLengthSid(low_buf)) ||
        !own_objects_as_user(restricted)) {
        CloseHandle(restricted);
        return nullptr;
    }
    return restricted;
}

HANDLE make_job() {
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) return nullptr;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim{};
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                           JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    lim.BasicLimitInformation.ActiveProcessLimit = 64;
    lim.JobMemoryLimit = 4ull << 30;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                                       JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                                       JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                                       JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS};
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof lim) ||
        !SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof ui)) {
        CloseHandle(job);
        return nullptr;
    }
    return job;
}

// Lets the low-integrity program write to its sandbox folder.
bool label_low(const std::wstring& dir) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1, &sd, nullptr))
        return false;
    PACL sacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted);
    DWORD rc = SetNamedSecurityInfoW(const_cast<wchar_t*>(dir.c_str()), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                                     nullptr, nullptr, nullptr, sacl);
    LocalFree(sd);
    return rc == ERROR_SUCCESS;
}

// Veyl.SandboxHook32.dll sits next to the 64-bit monitor.
std::wstring hook32_for(const std::wstring& hook64) {
    std::wstring p = hook64.substr(0, hook64.find_last_of(L"\\/") + 1) + L"Veyl.SandboxHook32.dll";
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES ? p : std::wstring();
}

std::vector<wchar_t> environment(const std::wstring& root, bool block_net) {
    std::vector<wchar_t> env;
    wchar_t* block = GetEnvironmentStringsW();
    for (wchar_t* p = block; *p; p += wcslen(p) + 1) {
        if (_wcsnicmp(p, L"VEYL_SANDBOX_", 13) == 0 || _wcsnicmp(p, L"__COMPAT_LAYER=", 15) == 0) continue;
        env.insert(env.end(), p, p + wcslen(p) + 1);
    }
    FreeEnvironmentStringsW(block);
    // RunAsInvoker makes Windows ignore a requireAdministrator manifest (most installers have one),
    // which would otherwise fail with ERROR_ELEVATION_REQUIRED. Children inherit it.
    for (std::wstring var : {L"VEYL_SANDBOX_ROOT=" + root, std::wstring(L"VEYL_SANDBOX_NET=") + (block_net ? L"block" : L"allow"),
                             std::wstring(L"__COMPAT_LAYER=RunAsInvoker")})
        env.insert(env.end(), var.c_str(), var.c_str() + var.size() + 1);
    env.push_back(L'\0');
    return env;
}

bool queue_dll(HANDLE process, HANDLE thread, const std::wstring& dll) {
    size_t bytes = (dll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote || !WriteProcessMemory(process, remote, dll.c_str(), bytes, nullptr)) return false;
    auto load = reinterpret_cast<PAPCFUNC>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    return QueueUserAPC(load, thread, reinterpret_cast<ULONG_PTR>(remote)) != 0;
}

}  // namespace
}  // namespace veyl

using namespace veyl;

VEYL_API int veyl_sandbox_start(const wchar_t* exe, const wchar_t* args, const wchar_t* root, const wchar_t* hook_dll,
                                int flags, VeylSandbox** out, int* out_pid, int* out_monitored) {
    if (!exe || !root || !out) return VEYL_ERR_ARG;
    *out = nullptr;
    std::wstring root_dir(root);
    CreateDirectoryW(root_dir.c_str(), nullptr);
    if (GetFileAttributesW(root_dir.c_str()) == INVALID_FILE_ATTRIBUTES || !label_low(root_dir)) return VEYL_ERR_IO;

    Handle token;
    token.h = make_token();
    if (!token.h) return VEYL_ERR_STATE;
    auto sb = new VeylSandbox();
    sb->job = make_job();
    if (!sb->job) {
        delete sb;
        return VEYL_ERR_STATE;
    }

    // 64-bit programs get Veyl.SandboxHook.dll, 32-bit ones Veyl.SandboxHook32.dll. Anything
    // else (ARM64) still runs fully sandboxed, just without the activity log.
    WORD machine = veyl_inject::exe_machine(exe);
    std::wstring hook64 = hook_dll ? hook_dll : L"";
    std::wstring hook32 = hook64.empty() ? L"" : hook32_for(hook64);
    bool monitor = !hook64.empty() && (machine == IMAGE_FILE_MACHINE_AMD64 || (machine == IMAGE_FILE_MACHINE_I386 && !hook32.empty()));
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\"";
    if (args && *args) cmd += L" " + std::wstring(args);
    std::wstring dir(exe);
    dir = dir.substr(0, dir.find_last_of(L"\\/"));
    auto env = environment(root_dir, !(flags & VEYL_SANDBOX_ALLOW_NETWORK));

    STARTUPINFOW si{sizeof si};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessAsUserW(token.h, exe, cmd.data(), nullptr, nullptr, FALSE,
                              CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, env.data(),
                              dir.c_str(), &si, &pi)) {
        DWORD err = GetLastError();
        delete sb;
        SetLastError(err);  // the caller reads it to explain the failure
        return err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ? VEYL_ERR_NOT_FOUND : VEYL_ERR_IO;
    }
    // Into the job before a single instruction runs, so nothing escapes it.
    if (!AssignProcessToJobObject(sb->job, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        delete sb;
        return VEYL_ERR_STATE;
    }
    if (monitor)
        monitor = machine == IMAGE_FILE_MACHINE_I386 ? veyl_inject::add_import32(pi.hProcess, hook32)
                                                     : queue_dll(pi.hProcess, pi.hThread, hook64);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    sb->process = pi.hProcess;
    sb->pid = pi.dwProcessId;
    if (out_pid) *out_pid = (int)pi.dwProcessId;
    if (out_monitored) *out_monitored = monitor ? 1 : 0;
    *out = sb;
    return VEYL_OK;
}

VEYL_API int veyl_sandbox_status(VeylSandbox* sb, int* active_processes, int* total_processes, int* exit_code) {
    if (!sb) return VEYL_ERR_ARG;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct{};
    if (!QueryInformationJobObject(sb->job, JobObjectBasicAccountingInformation, &acct, sizeof acct, nullptr))
        return VEYL_ERR_STATE;
    if (active_processes) *active_processes = (int)acct.ActiveProcesses;
    if (total_processes) *total_processes = (int)acct.TotalProcesses;
    DWORD code = 0;
    GetExitCodeProcess(sb->process, &code);
    if (exit_code) *exit_code = (int)code;
    return VEYL_OK;
}

VEYL_API int veyl_sandbox_kill(VeylSandbox* sb) {
    if (!sb) return VEYL_ERR_ARG;
    return TerminateJobObject(sb->job, 1) ? VEYL_OK : VEYL_ERR_STATE;
}

VEYL_API void veyl_sandbox_close(VeylSandbox* sb) { delete sb; }
