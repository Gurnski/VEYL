// Quarantine store. Each item is <dir>\<id>.vq:
//   char[8] magic "VEYLQRN\0", u32 version, i64 quarantined_at, u64 size,
//   u64 keystream seed, u32 path_len + UTF-16 path, u32 threat_len + UTF-16 threat,
//   then the file body XORed with a xorshift keystream.
// The obfuscation is only there to defang the file (no MZ header, no script text
// for other scanners or accidental double-clicks); it is not meant as secrecy.
#include "common.hpp"

namespace veyl {
namespace {

constexpr char kMagic[8] = {'V', 'E', 'Y', 'L', 'Q', 'R', 'N', '\0'};
constexpr uint32_t kVersion = 1;
constexpr uint64_t kMaxBytes = 512ull << 20;

void xor_stream(uint8_t* p, size_t n, uint64_t seed) {
    uint64_t x = seed | 1;
    for (size_t i = 0; i < n; i += 8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        for (size_t k = 0; k < 8 && i + k < n; ++k) p[i + k] ^= (uint8_t)(x >> (k * 8));
    }
}

void put(Bytes& b, const void* p, size_t n) { b.insert(b.end(), (const uint8_t*)p, (const uint8_t*)p + n); }

void put_wstr(Bytes& b, const std::wstring& s) {
    uint32_t n = (uint32_t)s.size();
    put(b, &n, 4);
    put(b, s.data(), n * sizeof(wchar_t));
}

struct Item {
    int64_t at = 0;
    uint64_t size = 0;
    uint64_t seed = 0;
    std::wstring path, threat;
    size_t body = 0;  // offset of the body
};

bool get_wstr(const Bytes& b, size_t& off, std::wstring& out) {
    uint32_t n;
    if (off + 4 > b.size()) return false;
    memcpy(&n, b.data() + off, 4);
    off += 4;
    if (n > 32768 || off + (size_t)n * 2 > b.size()) return false;
    out.assign((const wchar_t*)(b.data() + off), n);
    off += (size_t)n * 2;
    return true;
}

int parse(const Bytes& b, Item& it) {
    if (b.size() < 36 || memcmp(b.data(), kMagic, 8) != 0) return VEYL_ERR_FORMAT;
    uint32_t ver;
    memcpy(&ver, b.data() + 8, 4);
    if (ver != kVersion) return VEYL_ERR_FORMAT;
    memcpy(&it.at, b.data() + 12, 8);
    memcpy(&it.size, b.data() + 20, 8);
    memcpy(&it.seed, b.data() + 28, 8);
    size_t off = 36;
    if (!get_wstr(b, off, it.path) || !get_wstr(b, off, it.threat)) return VEYL_ERR_FORMAT;
    if (off + it.size != b.size()) return VEYL_ERR_FORMAT;
    it.body = off;
    return VEYL_OK;
}

bool valid_id(const wchar_t* id) {
    if (!id) return false;
    size_t n = wcslen(id);
    if (n == 0 || n > 36) return false;
    for (size_t i = 0; i < n; ++i)
        if (!iswxdigit(id[i]) && id[i] != L'-') return false;
    return true;
}

std::wstring item_path(const wchar_t* dir, const wchar_t* id) { return std::wstring(dir) + L"\\" + id + L".vq"; }

bool force_delete(const std::wstring& path) {
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(path.c_str()) != 0;
}

}  // namespace
}  // namespace veyl

using namespace veyl;

VEYL_API int veyl_quarantine_file(const wchar_t* path, const wchar_t* quarantine_dir, const wchar_t* threat,
                                  wchar_t out_id[37]) {
    if (!path || !quarantine_dir) return VEYL_ERR_ARG;
    CreateDirectoryW(quarantine_dir, nullptr);

    Bytes data;
    if (!read_file(path, data, kMaxBytes)) return VEYL_ERR_IO;

    std::wstring id = new_uuid();
    uint64_t seed;
    random_bytes((uint8_t*)&seed, sizeof seed);
    int64_t now = unix_now();
    uint64_t size = data.size();

    Bytes out;
    out.reserve(data.size() + 1024);
    put(out, kMagic, 8);
    put(out, &kVersion, 4);
    put(out, &now, 8);
    put(out, &size, 8);
    put(out, &seed, 8);
    put_wstr(out, path);
    put_wstr(out, threat ? threat : L"");
    xor_stream(data.data(), data.size(), seed);
    out.insert(out.end(), data.begin(), data.end());

    std::wstring dest = item_path(quarantine_dir, id.c_str());
    if (!write_file_atomic(dest, out.data(), out.size())) return VEYL_ERR_IO;
    DeleteFileW((dest + L".bak").c_str());

    if (!force_delete(path)) {
        // The original is in use; don't leave a duplicate in quarantine.
        DeleteFileW(dest.c_str());
        return VEYL_ERR_IO;
    }
    if (out_id) copy_fixed(id, out_id, 37);
    return VEYL_OK;
}

VEYL_API int veyl_quarantine_info(const wchar_t* quarantine_dir, const wchar_t* id, wchar_t* original_path,
                                  wchar_t* threat, int64_t* quarantined_at, int64_t* size) {
    if (!quarantine_dir || !valid_id(id)) return VEYL_ERR_ARG;
    // Only the header is needed, but items are small enough that reading it all is fine.
    Bytes b;
    if (!read_file(item_path(quarantine_dir, id), b, kMaxBytes + 70000)) return VEYL_ERR_NOT_FOUND;
    Item it;
    int rc = parse(b, it);
    if (rc != VEYL_OK) return rc;
    if (original_path) copy_fixed(it.path, original_path, 1024);
    if (threat) copy_fixed(it.threat, threat, 128);
    if (quarantined_at) *quarantined_at = it.at;
    if (size) *size = (int64_t)it.size;
    return VEYL_OK;
}

VEYL_API int veyl_quarantine_restore(const wchar_t* quarantine_dir, const wchar_t* id, const wchar_t* restore_to) {
    if (!quarantine_dir || !valid_id(id)) return VEYL_ERR_ARG;
    std::wstring src = item_path(quarantine_dir, id);
    Bytes b;
    if (!read_file(src, b, kMaxBytes + 70000)) return VEYL_ERR_NOT_FOUND;
    Item it;
    int rc = parse(b, it);
    if (rc != VEYL_OK) return rc;

    std::wstring dest = restore_to && *restore_to ? restore_to : it.path;
    if (GetFileAttributesW(dest.c_str()) != INVALID_FILE_ATTRIBUTES) return VEYL_ERR_EXISTS;

    uint8_t* body = b.data() + it.body;
    xor_stream(body, (size_t)it.size, it.seed);
    HANDLE h = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return VEYL_ERR_IO;
    DWORD written = 0;
    bool ok = WriteFile(h, body, (DWORD)it.size, &written, nullptr) && written == it.size;
    CloseHandle(h);
    if (!ok) {
        DeleteFileW(dest.c_str());
        return VEYL_ERR_IO;
    }
    force_delete(src);
    return VEYL_OK;
}

VEYL_API int veyl_quarantine_delete(const wchar_t* quarantine_dir, const wchar_t* id) {
    if (!quarantine_dir || !valid_id(id)) return VEYL_ERR_ARG;
    return force_delete(item_path(quarantine_dir, id)) ? VEYL_OK : VEYL_ERR_NOT_FOUND;
}
