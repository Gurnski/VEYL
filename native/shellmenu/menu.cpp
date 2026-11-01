// Veyl.ShellMenu.dll: "Run in VEYL sandbox" and "Scan with VEYL" in Windows 11's main
// right-click menu (the one before "Show more options").
//
// Windows 11 only puts IExplorerCommand handlers from a packaged app in that menu, so this
// DLL ships inside a sparse MSIX package (packaging/menu/AppxManifest.xml) whose files stay
// in the install folder. Explorer loads it in a COM surrogate (dllhost.exe), and each
// command just starts Veyl.App.exe with --sandbox or --scan, the same as the classic menu.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <shobjidl_core.h>
#include <shlwapi.h>

#include <atomic>
#include <string>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace {

// Must match packaging/menu/AppxManifest.xml.
constexpr CLSID kSandboxClsid = {0xa9ebffc4, 0xebdc, 0x4647, {0xb3, 0xc2, 0x0a, 0x8c, 0x37, 0x9c, 0x3e, 0x8a}};
constexpr CLSID kScanClsid = {0x7934491f, 0x812e, 0x4cc0, {0x89, 0xd3, 0xbd, 0x7d, 0xd0, 0x5f, 0xc7, 0x9f}};

HMODULE g_module = nullptr;
std::atomic<long> g_objects{0};

// Veyl.App.exe sits next to this DLL (the package's external location is the install folder).
std::wstring app_path() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_module, buf, MAX_PATH);
    std::wstring p(buf, n);
    return p.substr(0, p.find_last_of(L'\\') + 1) + L"Veyl.App.exe";
}

// Same list as SandboxService.Launcher: programs and the scripts it knows how to start.
bool sandboxable(const std::wstring& path) {
    const wchar_t* ext = PathFindExtensionW(path.c_str());
    for (const wchar_t* e : {L".exe", L".com", L".scr", L".bat", L".cmd", L".ps1", L".vbs", L".js", L".wsf"})
        if (_wcsicmp(ext, e) == 0) return true;
    return false;
}

// File-system path of the first selected item, or empty (e.g. a Control Panel item).
std::wstring first_path(IShellItemArray* items) {
    if (!items) return {};
    IShellItem* item = nullptr;
    if (FAILED(items->GetItemAt(0, &item))) return {};
    PWSTR name = nullptr;
    std::wstring path;
    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &name))) {
        path = name;
        CoTaskMemFree(name);
    }
    item->Release();
    return path;
}

DWORD selection_count(IShellItemArray* items) {
    DWORD n = 0;
    if (items) items->GetCount(&n);
    return n;
}

HRESULT dup(const wchar_t* text, PWSTR* out) { return SHStrDupW(text, out); }

class Command : public IExplorerCommand {
public:
    explicit Command(bool sandbox) : sandbox_(sandbox) { ++g_objects; }

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IExplorerCommand)) {
            *out = static_cast<IExplorerCommand*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        ULONG n = --refs_;
        if (n == 0) delete this;
        return n;
    }

    // IExplorerCommand
    IFACEMETHODIMP GetTitle(IShellItemArray*, PWSTR* name) override {
        return dup(sandbox_ ? L"Run in VEYL sandbox" : L"Scan with VEYL", name);
    }
    IFACEMETHODIMP GetIcon(IShellItemArray*, PWSTR* icon) override { return dup((app_path() + L",0").c_str(), icon); }
    IFACEMETHODIMP GetToolTip(IShellItemArray*, PWSTR* tip) override {
        *tip = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetCanonicalName(GUID* guid) override {
        *guid = sandbox_ ? kSandboxClsid : kScanClsid;
        return S_OK;
    }
    IFACEMETHODIMP GetState(IShellItemArray* items, BOOL, EXPCMDSTATE* state) override {
        // One item at a time, like the classic menu's %1. The sandbox entry only appears on
        // things it can run, so it doesn't clutter the menu on documents and pictures.
        std::wstring path = selection_count(items) == 1 ? first_path(items) : L"";
        bool show = !path.empty() && (!sandbox_ || (sandboxable(path) && !PathIsDirectoryW(path.c_str())));
        *state = show ? ECS_ENABLED : ECS_HIDDEN;
        return S_OK;
    }
    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) override {
        std::wstring path = first_path(items);
        if (path.empty()) return E_FAIL;
        std::wstring app = app_path();
        std::wstring cmd = L"\"" + app + L"\" " + (sandbox_ ? L"--sandbox" : L"--scan") + L" \"" + path + L"\"";
        STARTUPINFOW si{sizeof si};
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(app.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
            return HRESULT_FROM_WIN32(GetLastError());
        // Let the app take the foreground (it may hand the request to a copy already running).
        AllowSetForegroundWindow(pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return S_OK;
    }
    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* flags) override {
        *flags = ECF_DEFAULT;
        return S_OK;
    }
    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** out) override {
        *out = nullptr;
        return E_NOTIMPL;
    }

private:
    ~Command() { --g_objects; }
    std::atomic<ULONG> refs_{1};
    bool sandbox_;
};

class Factory : public IClassFactory {
public:
    explicit Factory(bool sandbox) : sandbox_(sandbox) {}
    IFACEMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *out = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    // Static objects: the factories live as long as the DLL.
    IFACEMETHODIMP_(ULONG) AddRef() override { return 2; }
    IFACEMETHODIMP_(ULONG) Release() override { return 1; }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* cmd = new (std::nothrow) Command(sandbox_);
        if (!cmd) return E_OUTOFMEMORY;
        HRESULT hr = cmd->QueryInterface(riid, out);
        cmd->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        lock ? ++g_objects : --g_objects;
        return S_OK;
    }

private:
    bool sandbox_;
};

Factory g_sandboxFactory(true);
Factory g_scanFactory(false);

}  // namespace

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** out) {
    if (clsid == kSandboxClsid) return g_sandboxFactory.QueryInterface(riid, out);
    if (clsid == kScanClsid) return g_scanFactory.QueryInterface(riid, out);
    if (out) *out = nullptr;
    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllCanUnloadNow() { return g_objects == 0 ? S_OK : S_FALSE; }

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
