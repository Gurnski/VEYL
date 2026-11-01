// Puts a secret on the clipboard, keeps it out of Win+V history and cloud
// clipboard, and wipes it again after a timeout.
#include "common.hpp"

#include <thread>

namespace veyl {

namespace {

bool set_dword_format(const wchar_t* name, DWORD value) {
    UINT fmt = RegisterClipboardFormatW(name);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
    if (!fmt || !mem) return false;
    *(DWORD*)GlobalLock(mem) = value;
    GlobalUnlock(mem);
    if (!SetClipboardData(fmt, mem)) {
        GlobalFree(mem);
        return false;
    }
    return true;
}

// OpenClipboard(NULL) followed by EmptyClipboard leaves no owner and makes
// SetClipboardData unreliable, so use a throwaway message-only window.
struct ClipboardOwner {
    HWND hwnd = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);
    bool open = false;
    ClipboardOwner() {
        for (int i = 0; i < 10 && !open; ++i) {
            open = OpenClipboard(hwnd);
            if (!open) Sleep(25);
        }
    }
    ~ClipboardOwner() {
        if (open) CloseClipboard();
        if (hwnd) DestroyWindow(hwnd);
    }
};

}  // namespace

bool clipboard_set_secret(const std::wstring& text, int clear_after_sec) {
    DWORD seq;
    {
        ClipboardOwner cb;
        if (!cb.open || !EmptyClipboard()) return false;

        size_t bytes = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!mem) return false;
        memcpy(GlobalLock(mem), text.c_str(), bytes);
        GlobalUnlock(mem);
        if (!SetClipboardData(CF_UNICODETEXT, mem)) {
            SecureZeroMemory(GlobalLock(mem), bytes);
            GlobalUnlock(mem);
            GlobalFree(mem);
            return false;
        }
        set_dword_format(L"ExcludeClipboardContentFromMonitorProcessing", 0);
        set_dword_format(L"CanIncludeInClipboardHistory", 0);
        set_dword_format(L"CanUploadToCloudClipboard", 0);
    }
    seq = GetClipboardSequenceNumber();

    if (clear_after_sec > 0) {
        std::thread([seq, clear_after_sec] {
            Sleep((DWORD)clear_after_sec * 1000);
            // Only clear if nothing else has been copied since.
            if (GetClipboardSequenceNumber() != seq) return;
            ClipboardOwner cb;
            if (cb.open) EmptyClipboard();
        }).detach();
    }
    return true;
}

}  // namespace veyl

VEYL_API int veyl_clipboard_set_secret(const wchar_t* text, int len, int clear_after_sec) {
    if (!text || len < 0) return VEYL_ERR_ARG;
    std::wstring s(text, (size_t)len);
    bool ok = veyl::clipboard_set_secret(s, clear_after_sec);
    SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
    return ok ? VEYL_OK : VEYL_ERR_IO;
}
