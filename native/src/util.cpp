#include "common.hpp"

#include <bcrypt.h>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")

namespace veyl {

std::string to_utf8(const wchar_t* s, int len) {
    if (!s) return {};
    if (len < 0) len = (int)wcslen(s);
    if (len == 0) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s, len, nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, len, out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

int copy_out(const std::wstring& src, wchar_t* buf, int* len) {
    if (!len) return VEYL_ERR_ARG;
    int need = (int)src.size() + 1;
    if (!buf || *len < need) {
        *len = need;
        return VEYL_ERR_BUFFER;
    }
    memcpy(buf, src.c_str(), need * sizeof(wchar_t));
    *len = need;
    return VEYL_OK;
}

void copy_fixed(const std::wstring& src, wchar_t* buf, size_t cap) {
    if (!buf || cap == 0) return;
    wcsncpy_s(buf, cap, src.c_str(), _TRUNCATE);
}

bool read_file(const std::wstring& path, Bytes& out, uint64_t max_bytes) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    bool ok = GetFileSizeEx(h, &size) && (uint64_t)size.QuadPart <= max_bytes;
    if (ok) {
        out.resize((size_t)size.QuadPart);
        size_t done = 0;
        while (ok && done < out.size()) {
            DWORD chunk = (DWORD)std::min<size_t>(out.size() - done, 1u << 24);
            DWORD got = 0;
            ok = ReadFile(h, out.data() + done, chunk, &got, nullptr) && got > 0;
            done += got;
        }
    }
    CloseHandle(h);
    return ok;
}

bool write_file_atomic(const std::wstring& path, const uint8_t* data, size_t size) {
    std::wstring tmp = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(h, data, (DWORD)size, &written, nullptr) && written == size;
    ok = ok && FlushFileBuffers(h);
    CloseHandle(h);
    if (ok) {
        // Keep the previous good copy around in case the new one is ever damaged.
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
            CopyFileW(path.c_str(), (path + L".bak").c_str(), FALSE);
        ok = MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (!ok) DeleteFileW(tmp.c_str());
    return ok;
}

int64_t unix_now() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{ft.dwLowDateTime, ft.dwHighDateTime};
    return (int64_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

std::wstring new_uuid() {
    UUID id;
    UuidCreate(&id);
    RPC_WSTR s = nullptr;
    UuidToStringW(&id, &s);
    std::wstring out(reinterpret_cast<wchar_t*>(s));
    RpcStringFreeW(&s);
    return out;
}

}  // namespace veyl

using namespace veyl;

VEYL_API const char* veyl_core_version(void) { return VEYL_CORE_VERSION; }

VEYL_API void veyl_secure_zero(void* p, int bytes) {
    if (p && bytes > 0) SecureZeroMemory(p, (size_t)bytes);
}

VEYL_API int veyl_generate_password(wchar_t* buf, int length, int flags) {
    if (!buf || length < 4 || length > 512) return VEYL_ERR_ARG;
    const bool no_amb = flags & VEYL_GEN_NO_AMBIGUOUS;
    std::wstring sets[4];
    if (flags & VEYL_GEN_LOWER) sets[0] = no_amb ? L"abcdefghijkmnpqrstuvwxyz" : L"abcdefghijklmnopqrstuvwxyz";
    if (flags & VEYL_GEN_UPPER) sets[1] = no_amb ? L"ABCDEFGHJKLMNPQRSTUVWXYZ" : L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (flags & VEYL_GEN_DIGITS) sets[2] = no_amb ? L"23456789" : L"0123456789";
    if (flags & VEYL_GEN_SYMBOLS) sets[3] = L"!@#$%^&*()-_=+[]{};:,.?/";

    std::wstring all;
    int used = 0;
    for (auto& s : sets)
        if (!s.empty()) { all += s; ++used; }
    if (all.empty() || length < used) return VEYL_ERR_ARG;

    // Unbiased index in [0, n) via rejection sampling.
    auto pick = [](size_t n) -> size_t {
        uint32_t limit = UINT32_MAX - (UINT32_MAX % (uint32_t)n);
        uint32_t r;
        do { random_bytes(reinterpret_cast<uint8_t*>(&r), sizeof r); } while (r >= limit);
        return r % n;
    };

    // Regenerate until every selected class appears at least once.
    for (;;) {
        for (int i = 0; i < length; ++i) buf[i] = all[pick(all.size())];
        buf[length] = L'\0';
        bool ok = true;
        for (auto& s : sets) {
            if (s.empty()) continue;
            bool found = false;
            for (int i = 0; i < length && !found; ++i) found = s.find(buf[i]) != std::wstring::npos;
            ok = ok && found;
        }
        if (ok) return VEYL_OK;
    }
}

VEYL_API int veyl_sha256_file(const wchar_t* path, char out_hex[65]) {
    if (!path || !out_hex) return VEYL_ERR_ARG;
    Digests d;
    int rc = hash_file(path, 0, d);
    if (rc == VEYL_OK) memcpy(out_hex, hex(d.sha256, 32).c_str(), 65);
    return rc;
}
