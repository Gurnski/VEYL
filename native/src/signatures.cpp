// Signature packs: validation, lookup and the compiler that turns hash lists
// (VirusShare .md5 files, "hash name" text, older packs) into one sorted pack.
#include "sigdb.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <unordered_map>

namespace veyl {

const wchar_t* hash_kind_name(int kind) {
    static const wchar_t* names[] = {L"MD5", L"SHA-1", L"SHA-256"};
    return kind >= 0 && kind < kHashKinds ? names[kind] : L"?";
}

int hash_kind_for_hex_len(size_t len) {
    for (int k = 0; k < kHashKinds; ++k)
        if (len == kDigestLen[k] * 2) return k;
    return -1;
}

// ---------------------------------------------------------------- reading
std::unique_ptr<SigPack> SigPack::open(const std::wstring& path, int* status) {
    auto fail = [&](int rc) -> std::unique_ptr<SigPack> {
        if (status) *status = rc;
        return nullptr;
    };
    // Share-delete so a newer pack can supersede this one while it's mapped.
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return fail(VEYL_ERR_NOT_FOUND);
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart < (LONGLONG)sizeof(PackHeader)) {
        CloseHandle(f);
        return fail(VEYL_ERR_FORMAT);
    }
    HANDLE m = CreateFileMappingW(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(f);
    if (!m) return fail(VEYL_ERR_IO);
    auto base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(m);  // the view keeps the file mapped
    if (!base) return fail(VEYL_ERR_IO);

    std::unique_ptr<SigPack> p(new SigPack());
    p->base_ = base;
    p->size_ = (uint64_t)size.QuadPart;
    p->path_ = path;

    // The signatures folder is writable by every user, so nothing in here is trusted:
    // every offset and count is checked against the file size before use.
    const PackHeader& h = p->hdr();
    if (memcmp(h.magic, kPackMagic, 8) != 0 || h.version != kPackVersion || h.header_size != sizeof(PackHeader) ||
        memchr(h.label, 0, sizeof h.label) == nullptr)
        return fail(VEYL_ERR_FORMAT);
    p->label_ = to_wide(h.label);

    const uint64_t n = p->size_;
    auto fits = [n](uint64_t off, uint64_t len) { return off <= n && len <= n - off; };

    if (h.name_count) {
        if (h.name_count > (1u << 26) || !fits(h.names_offset, h.names_size) ||
            (uint64_t)(h.name_count + 1) * 4 > h.names_size)
            return fail(VEYL_ERR_FORMAT);
        p->name_offsets_ = reinterpret_cast<const uint32_t*>(base + h.names_offset);
        p->name_blob_ = reinterpret_cast<const char*>(base + h.names_offset + (uint64_t)(h.name_count + 1) * 4);
        p->name_blob_size_ = h.names_size - (uint64_t)(h.name_count + 1) * 4;
        p->name_count_ = h.name_count;
        uint32_t prev = 0;
        for (uint32_t i = 0; i <= h.name_count; ++i) {
            uint32_t o;
            memcpy(&o, p->name_offsets_ + i, 4);
            if (o < prev || o > p->name_blob_size_) return fail(VEYL_ERR_FORMAT);
            prev = o;
        }
    }

    for (int k = 0; k < kHashKinds; ++k) {
        const PackSection& s = h.sections[k];
        if (s.count == 0) continue;
        bool named = s.flags & kSectionNamed, indexed = s.flags & kSectionIndexed;
        if ((s.flags & ~(kSectionNamed | kSectionIndexed)) || s.width != kDigestLen[k] + (named ? 4 : 0) ||
            s.count > 0xFFFFFFFFull || (named && h.name_count == 0))
            return fail(VEYL_ERR_FORMAT);
        uint64_t off = s.offset;
        if (off < sizeof(PackHeader)) return fail(VEYL_ERR_FORMAT);
        Section& sec = p->sec_[k];
        if (indexed) {
            if (!fits(off, kIndexSlots * 4ull)) return fail(VEYL_ERR_FORMAT);
            sec.index = reinterpret_cast<const uint32_t*>(base + off);
            uint32_t prev = 0;
            for (uint32_t i = 0; i < kIndexSlots; ++i) {
                uint32_t v;
                memcpy(&v, sec.index + i, 4);
                if (v < prev || v > s.count || (i == 0 && v != 0)) return fail(VEYL_ERR_FORMAT);
                prev = v;
            }
            if (prev != s.count) return fail(VEYL_ERR_FORMAT);
            off += kIndexSlots * 4ull;
        }
        if (s.count > n / s.width || !fits(off, s.count * s.width)) return fail(VEYL_ERR_FORMAT);
        sec.entries = base + off;
        sec.count = s.count;
        sec.width = s.width;
        sec.named = named;
    }
    if (status) *status = VEYL_OK;
    return p;
}

SigPack::~SigPack() {
    if (base_) UnmapViewOfFile(base_);
}

std::string SigPack::name_at(uint32_t id) const {
    if (id == 0 || id >= name_count_) return {};
    uint32_t a, b;
    memcpy(&a, name_offsets_ + id, 4);
    memcpy(&b, name_offsets_ + id + 1, 4);
    return std::string(name_blob_ + a, b - a);
}

std::string SigPack::entry_name(int kind, uint64_t i) const {
    const Section& s = sec_[kind];
    if (!s.named) return {};
    uint32_t id;
    memcpy(&id, s.entries + i * s.width + kDigestLen[kind], 4);
    return name_at(id);
}

bool SigPack::find(int kind, const uint8_t* digest, std::wstring& name) const {
    const Section& s = sec_[kind];
    if (s.count == 0) return false;
    const size_t len = kDigestLen[kind];
    uint64_t lo = 0, hi = s.count;
    if (s.index) {
        uint32_t prefix = (uint32_t)digest[0] << 8 | digest[1];
        uint32_t a, b;
        memcpy(&a, s.index + prefix, 4);
        memcpy(&b, s.index + prefix + 1, 4);
        lo = a;
        hi = b;
    }
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        int c = memcmp(s.entries + mid * s.width, digest, len);
        if (c == 0) {
            std::string own = entry_name(kind, mid);
            name = own.empty() ? label_ : to_wide(own);
            return true;
        }
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

// ---------------------------------------------------------------- compiling
namespace {

template <size_t N>
struct Entry {
    std::array<uint8_t, N> d;
    uint32_t name;
};

struct Builder {
    std::vector<Entry<16>> md5;
    std::vector<Entry<20>> sha1;
    std::vector<Entry<32>> sha256;
    std::vector<std::string> names{""};
    std::unordered_map<std::string, uint32_t> name_ids{{"", 0}};

    uint32_t intern(const std::string& s) {
        if (s.empty()) return 0;
        auto [it, fresh] = name_ids.try_emplace(s, (uint32_t)names.size());
        if (fresh) names.push_back(s);
        return it->second;
    }

    void add(int kind, const uint8_t* d, uint32_t name) {
        auto put = [&](auto& v) {
            auto& e = v.emplace_back();
            memcpy(e.d.data(), d, e.d.size());
            e.name = name;
        };
        if (kind == kMd5) put(md5);
        else if (kind == kSha1) put(sha1);
        else put(sha256);
    }

    // Sorts and removes duplicates. A named entry beats an unnamed one for the same hash.
    template <size_t N>
    static void finish(std::vector<Entry<N>>& v) {
        std::sort(v.begin(), v.end(), [](const Entry<N>& a, const Entry<N>& b) { return a.d < b.d; });
        size_t out = 0;
        for (size_t i = 0; i < v.size(); ++i) {
            if (out > 0 && v[out - 1].d == v[i].d) {
                if (v[out - 1].name == 0) v[out - 1].name = v[i].name;
                continue;
            }
            v[out++] = v[i];
        }
        v.resize(out);
    }
};

bool is_sep(char c) { return c == ' ' || c == '\t' || c == ',' || c == ';' || c == '"' || c == '\''; }

// "hash", "hash name", "hash,name", "\"hash\",\"name\"". Anything else is skipped.
void parse_line(const char* p, size_t n, Builder& b) {
    while (n && (p[n - 1] == '\r' || p[n - 1] == ' ' || p[n - 1] == '\t')) --n;
    size_t i = 0;
    while (i < n && is_sep(p[i])) ++i;
    if (i == n || p[i] == '#') return;
    size_t j = i;
    while (j < n && isxdigit((unsigned char)p[j])) ++j;
    int kind = hash_kind_for_hex_len(j - i);
    if (kind < 0 || (j < n && !is_sep(p[j]))) return;
    uint8_t d[32];
    if (!unhex(p + i, kDigestLen[kind], d)) return;
    while (j < n && is_sep(p[j])) ++j;
    size_t end = n;
    while (end > j && is_sep(p[end - 1])) --end;
    size_t len = std::min<size_t>(end - j, 120);
    while (len > 0 && len < end - j && ((unsigned char)p[j + len] & 0xC0) == 0x80) --len;  // don't split a UTF-8 character
    b.add(kind, d, b.intern(std::string(p + j, len)));
}

int read_text_list(const std::wstring& path, Builder& b) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return VEYL_ERR_NOT_FOUND;
    std::vector<char> buf(4 << 20);
    std::string carry;
    bool first = true, ok = true;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(f, buf.data(), (DWORD)buf.size(), &got, nullptr)) { ok = false; break; }
        if (got == 0) break;
        const char* p = buf.data();
        size_t n = got;
        if (first && n >= 3 && memcmp(p, "\xEF\xBB\xBF", 3) == 0) { p += 3; n -= 3; }
        first = false;
        size_t start = 0;
        for (size_t i = 0; i < n; ++i) {
            if (p[i] != '\n') continue;
            if (!carry.empty()) {
                carry.append(p + start, i - start);
                parse_line(carry.data(), carry.size(), b);
                carry.clear();
            } else {
                parse_line(p + start, i - start, b);
            }
            start = i + 1;
        }
        if (carry.size() < (1 << 20)) carry.append(p + start, n - start);  // a 1 MB "line" isn't a hash list
    }
    if (!carry.empty()) parse_line(carry.data(), carry.size(), b);
    CloseHandle(f);
    return ok ? VEYL_OK : VEYL_ERR_IO;
}

int read_input(const std::wstring& path, Builder& b) {
    char magic[8]{};
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return VEYL_ERR_NOT_FOUND;
    DWORD got = 0;
    ReadFile(f, magic, 8, &got, nullptr);
    CloseHandle(f);
    if (got < 8 || memcmp(magic, kPackMagic, 8) != 0) return read_text_list(path, b);

    int rc = VEYL_OK;
    auto pack = SigPack::open(path, &rc);
    if (!pack) return rc;
    for (int k = 0; k < kHashKinds; ++k)
        for (uint64_t i = 0; i < pack->count(k); ++i) b.add(k, pack->entry(k, i), b.intern(pack->entry_name(k, i)));
    return VEYL_OK;
}

// Buffered writer that also hashes everything it writes.
struct PackWriter {
    HANDLE f;
    BCRYPT_HASH_HANDLE h = nullptr;
    std::vector<uint8_t> buf;
    uint64_t pos = 0;
    bool ok = true;

    explicit PackWriter(HANDLE file) : f(file) {
        buf.reserve(1 << 20);
        ok = BCRYPT_SUCCESS(BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &h, nullptr, 0, nullptr, 0, 0));
    }
    ~PackWriter() {
        if (h) BCryptDestroyHash(h);
    }
    void flush() {
        if (buf.empty() || !ok) return;
        DWORD w = 0;
        ok = BCRYPT_SUCCESS(BCryptHashData(h, buf.data(), (ULONG)buf.size(), 0)) &&
             WriteFile(f, buf.data(), (DWORD)buf.size(), &w, nullptr) && w == buf.size();
        buf.clear();
    }
    void put(const void* p, size_t n) {
        auto b = (const uint8_t*)p;
        while (n) {
            size_t take = std::min(n, buf.capacity() - buf.size());
            buf.insert(buf.end(), b, b + take);
            b += take;
            n -= take;
            pos += take;
            if (buf.size() == buf.capacity()) flush();
        }
    }
    bool finish(uint8_t out[32]) {
        flush();
        return ok && BCRYPT_SUCCESS(BCryptFinishHash(h, out, 32, 0));
    }
};

template <size_t N>
void write_section(PackWriter& w, const std::vector<Entry<N>>& v, bool named, PackSection& s) {
    s.offset = sizeof(PackHeader) + w.pos;
    s.count = v.size();
    s.width = (uint32_t)(N + (named ? 4 : 0));
    s.flags = named ? kSectionNamed : 0;
    if (v.empty()) return;
    if (v.size() >= kIndexMinEntries) {
        s.flags |= kSectionIndexed;
        std::vector<uint32_t> index(kIndexSlots);
        size_t i = 0;
        for (uint32_t prefix = 0; prefix < 65536; ++prefix) {
            index[prefix] = (uint32_t)i;
            while (i < v.size() && ((uint32_t)v[i].d[0] << 8 | v[i].d[1]) == prefix) ++i;
        }
        index[65536] = (uint32_t)v.size();
        w.put(index.data(), index.size() * 4);
    }
    for (const auto& e : v) {
        w.put(e.d.data(), N);
        if (named) w.put(&e.name, 4);
    }
}

std::wstring safe_file_label(const std::wstring& label) {
    std::wstring s;
    for (wchar_t c : label) {
        if (s.size() >= 40) break;
        s += iswalnum(c) || c == L'-' || c == L'_' ? c : L'_';
    }
    return s.empty() ? L"pack" : s;
}

}  // namespace
}  // namespace veyl

using namespace veyl;

VEYL_API int veyl_signature_compile(const wchar_t* const* inputs, int input_count, const wchar_t* label,
                                    const wchar_t* out_dir, wchar_t out_path[260], int64_t* out_hashes) {
    if (!inputs || input_count <= 0 || !label || !*label || !out_dir) return VEYL_ERR_ARG;
    std::string label8 = to_utf8(label);
    if (label8.size() > 63) return VEYL_ERR_ARG;

    // Reserve up front: growing a 30-million-entry vector by doubling briefly needs
    // twice the memory. A bare MD5 line is 33 bytes; packs know their own counts.
    Builder b;
    uint64_t md5_guess = 0, sha1_guess = 0, sha256_guess = 0;
    for (int i = 0; i < input_count; ++i) {
        if (!inputs[i]) return VEYL_ERR_ARG;
        if (auto pack = SigPack::open(inputs[i])) {
            md5_guess += pack->count(kMd5);
            sha1_guess += pack->count(kSha1);
            sha256_guess += pack->count(kSha256);
            continue;
        }
        WIN32_FILE_ATTRIBUTE_DATA a;
        size_t len = wcslen(inputs[i]);
        if (len > 4 && _wcsicmp(inputs[i] + len - 4, L".md5") == 0 &&
            GetFileAttributesExW(inputs[i], GetFileExInfoStandard, &a))
            md5_guess += (((uint64_t)a.nFileSizeHigh << 32) | a.nFileSizeLow) / 33;
    }
    b.md5.reserve((size_t)std::min<uint64_t>(md5_guess, 1ull << 31));
    b.sha1.reserve((size_t)std::min<uint64_t>(sha1_guess, 1ull << 31));
    b.sha256.reserve((size_t)std::min<uint64_t>(sha256_guess, 1ull << 31));
    for (int i = 0; i < input_count; ++i)
        if (int rc = read_input(inputs[i], b); rc != VEYL_OK) return rc;
    Builder::finish(b.md5);
    Builder::finish(b.sha1);
    Builder::finish(b.sha256);
    uint64_t total = b.md5.size() + b.sha1.size() + b.sha256.size();
    if (total == 0) return VEYL_ERR_FORMAT;  // nothing that looked like a hash
    if (b.md5.size() > 0xFFFFFFFFull || b.sha1.size() > 0xFFFFFFFFull || b.sha256.size() > 0xFFFFFFFFull)
        return VEYL_ERR_ARG;

    PackHeader h{};
    memcpy(h.magic, kPackMagic, 8);
    h.version = kPackVersion;
    h.header_size = sizeof(PackHeader);
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    h.created = ((uint64_t)now.dwHighDateTime << 32) | now.dwLowDateTime;
    memcpy(h.label, label8.data(), label8.size());

    // Named "<label>-<created>.vdb": never the name of a pack that might be mapped right now.
    wchar_t stamp[17];
    swprintf_s(stamp, L"%016llx", (unsigned long long)h.created);
    std::wstring dir(out_dir);
    while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
    std::wstring final_path = dir + L"\\" + safe_file_label(label) + L"-" + stamp + L".vdb";
    std::wstring tmp = final_path + L".tmp";

    HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return VEYL_ERR_IO;

    bool named = b.names.size() > 1;
    PackWriter w(f);
    {
        PackHeader placeholder{};
        DWORD wr = 0;
        w.ok = w.ok && WriteFile(f, &placeholder, sizeof placeholder, &wr, nullptr) && wr == sizeof placeholder;
    }
    write_section(w, b.md5, named, h.sections[kMd5]);
    write_section(w, b.sha1, named, h.sections[kSha1]);
    write_section(w, b.sha256, named, h.sections[kSha256]);
    if (named) {
        h.names_offset = sizeof(PackHeader) + w.pos;
        h.name_count = (uint32_t)b.names.size();
        uint32_t off = 0;
        for (const auto& n : b.names) {
            w.put(&off, 4);
            off += (uint32_t)n.size();
        }
        w.put(&off, 4);
        for (const auto& n : b.names) w.put(n.data(), n.size());
        h.names_size = sizeof(PackHeader) + w.pos - h.names_offset;
    }
    bool ok = w.finish(h.content_sha256);
    if (ok) {
        LARGE_INTEGER zero{};
        DWORD wr = 0;
        ok = SetFilePointerEx(f, zero, nullptr, FILE_BEGIN) && WriteFile(f, &h, sizeof h, &wr, nullptr) &&
             wr == sizeof h && FlushFileBuffers(f);
    }
    CloseHandle(f);
    if (!ok || !MoveFileExW(tmp.c_str(), final_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return VEYL_ERR_IO;
    }
    // Older packs with the same label are cleaned up the next time the scanner loads.
    if (out_path) copy_fixed(final_path, out_path, 260);
    if (out_hashes) *out_hashes = (int64_t)total;
    return VEYL_OK;
}

VEYL_API int veyl_signature_pack_info(const wchar_t* path, wchar_t label[64], int64_t* md5, int64_t* sha1,
                                      int64_t* sha256) {
    if (!path) return VEYL_ERR_ARG;
    int rc = VEYL_OK;
    auto p = SigPack::open(path, &rc);
    if (!p) return rc;
    if (label) copy_fixed(p->label(), label, 64);
    if (md5) *md5 = (int64_t)p->count(kMd5);
    if (sha1) *sha1 = (int64_t)p->count(kSha1);
    if (sha256) *sha256 = (int64_t)p->count(kSha256);
    return VEYL_OK;
}
