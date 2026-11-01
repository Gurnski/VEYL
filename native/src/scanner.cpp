// File scanner: hash blocklist (MD5, SHA-1 and SHA-256, from hashes.txt and from
// signature packs), optional AMSI (Windows Defender engine) pass, and static
// heuristics for PE files and scripts.
#include "common.hpp"
#include "sigdb.hpp"

#include <amsi.h>
#include <softpub.h>
#include <wintrust.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <thread>
#include <climits>
#include <cmath>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "wintrust.lib")

namespace veyl {
namespace {

constexpr uint64_t kMaxHeuristicBytes = 64ull << 20;
constexpr uint64_t kMaxHashBytes = 512ull << 20;
constexpr uint64_t kMaxAmsiBytes = 16ull << 20;
constexpr int kSuspiciousScore = 50;

struct Scanner {
    std::shared_mutex sig_lock;
    // hashes.txt and hashes added at runtime, keyed by the raw digest bytes (16, 20 or
    // 32 of them, so the three hash kinds can share one map).
    std::unordered_map<std::string, std::wstring> manual;
    std::vector<std::unique_ptr<SigPack>> packs;
    std::atomic<int> want{0};  // kWant* bits: which extra digests scans need to compute
    bool initialised = false;

    std::mutex amsi_lock;
    HAMSICONTEXT amsi = nullptr;
};

Scanner& scanner() {
    static Scanner s;
    return s;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
    return s;
}

std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), towlower);
    return s;
}

// "hex digest" -> raw bytes key for Scanner::manual. Empty if it isn't an MD5, SHA-1 or SHA-256.
std::string digest_key(const std::string& hexstr) {
    int kind = hash_kind_for_hex_len(hexstr.size());
    if (kind < 0) return {};
    std::string key(kDigestLen[kind], '\0');
    return unhex(hexstr.data(), key.size(), (uint8_t*)key.data()) ? key : std::string();
}

double entropy(const uint8_t* p, size_t n) {
    if (n == 0) return 0;
    size_t counts[256]{};
    for (size_t i = 0; i < n; ++i) counts[p[i]]++;
    double e = 0;
    for (size_t c : counts) {
        if (!c) continue;
        double f = (double)c / n;
        e -= f * std::log2(f);
    }
    return e;
}

struct Findings {
    int score = 0;
    std::wstring reasons;
    void add(int pts, const wchar_t* why) {
        score += pts;
        if (!reasons.empty()) reasons += L"; ";
        reasons += why;
    }
};

// ---------------------------------------------------------------- PE parsing
struct PeView {
    const uint8_t* base;
    size_t size;
    const IMAGE_NT_HEADERS* nt = nullptr;
    const IMAGE_SECTION_HEADER* sections = nullptr;
    int nsections = 0;
    bool is64 = false;

    template <typename T>
    const T* at(size_t off) const {
        return off + sizeof(T) <= size ? reinterpret_cast<const T*>(base + off) : nullptr;
    }

    bool parse() {
        auto dos = at<IMAGE_DOS_HEADER>(0);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
        nt = at<IMAGE_NT_HEADERS>((size_t)dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
        is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        size_t sec_off = (size_t)dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
        nsections = nt->FileHeader.NumberOfSections;
        if (nsections <= 0 || nsections > 96 || sec_off + nsections * sizeof(IMAGE_SECTION_HEADER) > size) return false;
        sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sec_off);
        return true;
    }

    uint32_t entry_rva() const {
        return is64 ? reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt)->OptionalHeader.AddressOfEntryPoint
                    : reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt)->OptionalHeader.AddressOfEntryPoint;
    }

    IMAGE_DATA_DIRECTORY dir(int idx) const {
        if (is64) {
            auto& oh = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt)->OptionalHeader;
            return idx < (int)oh.NumberOfRvaAndSizes ? oh.DataDirectory[idx] : IMAGE_DATA_DIRECTORY{};
        }
        auto& oh = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt)->OptionalHeader;
        return idx < (int)oh.NumberOfRvaAndSizes ? oh.DataDirectory[idx] : IMAGE_DATA_DIRECTORY{};
    }

    int section_of(uint32_t rva) const {
        for (int i = 0; i < nsections; ++i) {
            uint32_t va = sections[i].VirtualAddress;
            uint32_t vs = std::max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
            if (rva >= va && rva < va + vs) return i;
        }
        return -1;
    }

    // Returns 0 when the RVA does not map to file data.
    size_t rva_to_off(uint32_t rva) const {
        int i = section_of(rva);
        if (i < 0) return 0;
        size_t off = (size_t)sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
        return off < size ? off : 0;
    }

    std::string cstr(size_t off, size_t max = 256) const {
        std::string s;
        while (off < size && base[off] && s.size() < max) s += (char)base[off++];
        return s;
    }

    // Collects imported function names (lower case). Ordinal imports are skipped.
    void imports(std::unordered_set<std::string>& out, int& dll_count) const {
        dll_count = 0;
        auto d = dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
        size_t off = d.VirtualAddress ? rva_to_off(d.VirtualAddress) : 0;
        if (!off) return;
        for (int n = 0; n < 512; ++n, off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            auto desc = at<IMAGE_IMPORT_DESCRIPTOR>(off);
            if (!desc || (!desc->Name && !desc->FirstThunk)) break;
            ++dll_count;
            uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            size_t toff = rva_to_off(thunk_rva);
            if (!toff) continue;
            for (int k = 0; k < 4096; ++k) {
                uint64_t t;
                if (is64) {
                    auto p = at<uint64_t>(toff + k * 8);
                    if (!p) break;
                    t = *p;
                    if (!t) break;
                    if (t & IMAGE_ORDINAL_FLAG64) continue;
                } else {
                    auto p = at<uint32_t>(toff + k * 4);
                    if (!p) break;
                    t = *p;
                    if (!t) break;
                    if (t & IMAGE_ORDINAL_FLAG32) continue;
                }
                size_t name_off = rva_to_off((uint32_t)t);
                if (name_off) out.insert(lower(cstr(name_off + 2)));
            }
        }
    }
};

bool has_any(const std::unordered_set<std::string>& imps, std::initializer_list<const char*> names) {
    for (auto n : names)
        if (imps.count(n)) return true;
    return false;
}

void pe_heuristics(const Bytes& data, Findings& f) {
    PeView pe{data.data(), data.size()};
    if (!pe.parse()) {
        f.add(10, L"Malformed PE headers");
        return;
    }

    static const char* packers[] = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".nsp0",
                                    ".nsp1", "mpress1", "mpress2", ".themida", ".vmp0", ".vmp1", ".enigma1"};
    bool packer_named = false, high_entropy_code = false, wx = false;
    for (int i = 0; i < pe.nsections; ++i) {
        const auto& s = pe.sections[i];
        std::string name = lower(std::string((const char*)s.Name, strnlen((const char*)s.Name, 8)));
        for (auto p : packers) packer_named |= name == p;
        bool exec = s.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        bool write = s.Characteristics & IMAGE_SCN_MEM_WRITE;
        wx |= exec && write;
        if (exec && s.PointerToRawData < data.size() && s.SizeOfRawData > 4096) {
            size_t n = std::min<size_t>(s.SizeOfRawData, data.size() - s.PointerToRawData);
            high_entropy_code |= entropy(data.data() + s.PointerToRawData, n) > 7.2;
        }
    }
    if (packer_named) f.add(20, L"Known packer section names");
    if (high_entropy_code) f.add(20, L"Encrypted or compressed code section");
    if (wx) f.add(15, L"Writable and executable section");

    uint32_t ep = pe.entry_rva();
    if (ep) {
        int sec = pe.section_of(ep);
        if (sec < 0) f.add(20, L"Entry point outside all sections");
        else if (!(pe.sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) f.add(20, L"Entry point in non-executable section");
        else if (sec == pe.nsections - 1 && pe.nsections > 2) f.add(10, L"Entry point in last section");
    }

    std::unordered_set<std::string> imps;
    int dlls = 0;
    pe.imports(imps, dlls);
    bool is_dll = pe.nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
    if (!is_dll && imps.size() < 5 && (packer_named || high_entropy_code))
        f.add(15, L"Very small import table (likely packed)");

    bool remote_alloc = has_any(imps, {"virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory"});
    bool remote_write = has_any(imps, {"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"});
    bool remote_exec = has_any(imps, {"createremotethread", "createremotethreadex", "ntcreatethreadex",
                                      "queueuserapc", "ntqueueapcthread", "setthreadcontext"});
    if (remote_alloc && remote_write && remote_exec) f.add(35, L"Process injection API combination");
    if (has_any(imps, {"setwindowshookexa", "setwindowshookexw"}) &&
        has_any(imps, {"getasynckeystate", "getkeyboardstate"}))
        f.add(15, L"Keyboard hook and key state polling");
    if (has_any(imps, {"isdebuggerpresent", "checkremotedebuggerpresent"}) &&
        has_any(imps, {"ntqueryinformationprocess"}))
        f.add(5, L"Anti-debugging checks");
    if (has_any(imps, {"cryptencrypt", "bcryptencrypt"}) && has_any(imps, {"findfirstfilew", "findfirstfileexw"}) &&
        has_any(imps, {"movefileexw", "deletefilew"}))
        f.add(10, L"Bulk file encryption capability");
}

void script_heuristics(const Bytes& data, Findings& f) {
    std::string text = lower(std::string((const char*)data.data(), std::min<size_t>(data.size(), 4 << 20)));
    struct Rule { const char* needle; int pts; const wchar_t* why; };
    static const Rule rules[] = {
        {"-encodedcommand", 20, L"Encoded PowerShell command"},
        {" -enc ", 20, L"Encoded PowerShell command"},
        {"frombase64string", 10, L"Base64 decoding"},
        {"invoke-expression", 15, L"Dynamic code execution (Invoke-Expression)"},
        {"iex(", 15, L"Dynamic code execution (iex)"},
        {"downloadstring", 20, L"Downloads and runs remote content"},
        {"downloadfile", 10, L"Downloads remote files"},
        {"net.webclient", 10, L"Web client usage"},
        {"-executionpolicy bypass", 15, L"Execution policy bypass"},
        {"-windowstyle hidden", 15, L"Hidden window"},
        {"wscript.shell", 10, L"Shell object creation"},
        {"vssadmin delete shadows", 40, L"Deletes volume shadow copies"},
        {"bcdedit /set {default} recoveryenabled no", 40, L"Disables recovery"},
        {"set-mppreference -disable", 40, L"Disables Windows Defender"},
        {"add-mppreference -exclusionpath", 30, L"Adds Defender exclusions"},
    };
    for (const auto& r : rules)
        if (text.find(r.needle) != std::string::npos) f.add(r.pts, r.why);
}

bool has_valid_signature(const std::wstring& path) {
    WINTRUST_FILE_INFO file{sizeof file};
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd{sizeof wd};
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &file;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(nullptr, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    return st == ERROR_SUCCESS;
}

bool amsi_detects(const Bytes& data, const std::wstring& path) {
    auto& s = scanner();
    std::lock_guard g(s.amsi_lock);
    if (!s.amsi) return false;
    AMSI_RESULT r = AMSI_RESULT_CLEAN;
    if (FAILED(AmsiScanBuffer(s.amsi, (PVOID)data.data(), (ULONG)data.size(), path.c_str(), nullptr, &r)))
        return false;
    return AmsiResultIsMalware(r);
}

std::wstring extension(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash)) return {};
    return lower(path.substr(dot));
}

bool is_script_ext(const std::wstring& ext) {
    static const wchar_t* exts[] = {L".ps1", L".psm1", L".bat", L".cmd", L".vbs", L".vbe",
                                    L".js", L".jse", L".hta", L".wsf"};
    for (auto e : exts)
        if (ext == e) return true;
    return false;
}

bool starts_with_mz(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char mz[2]{};
    DWORD got = 0;
    bool ok = ReadFile(h, mz, 2, &got, nullptr) && got == 2 && mz[0] == 'M' && mz[1] == 'Z';
    CloseHandle(h);
    return ok;
}

// "invoice.pdf.exe" style names.
bool double_extension(const std::wstring& path) {
    static const wchar_t* decoys[] = {L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".jpg", L".png", L".txt", L".mp4", L".zip"};
    std::wstring name = lower(path.substr(path.find_last_of(L"\\/") + 1));
    size_t last = name.find_last_of(L'.');
    if (last == std::wstring::npos || last == 0) return false;
    std::wstring rest = name.substr(0, last);
    for (auto d : decoys)
        if (rest.size() > wcslen(d) && rest.compare(rest.size() - wcslen(d), wcslen(d), d) == 0) return true;
    return false;
}

void fill(VeylScanResult* out, int verdict, int score, const std::wstring& threat, const std::wstring& detail) {
    out->verdict = verdict;
    out->score = std::min(score, 100);
    copy_fixed(threat, out->threat, 128);
    copy_fixed(detail, out->detail, 256);
}

// Large media files can't run on their own. If they don't start with MZ they're not
// worth hashing against a blocklist of malware hashes.
bool is_inert_media(const std::wstring& ext) {
    static const wchar_t* exts[] = {L".mp4", L".mkv", L".mov", L".avi", L".wmv", L".webm", L".mp3", L".flac", L".wav",
                                    L".ogg", L".m4a", L".jpg", L".jpeg", L".png", L".gif", L".bmp", L".webp", L".heic",
                                    L".psd", L".raw", L".cr2", L".nef", L".vhdx", L".vmdk", L".pak", L".bik", L".pdb"};
    for (auto e : exts)
        if (ext == e) return true;
    return false;
}

// ---------------------------------------------------------------- hash lists
// Call with sig_lock held exclusively.
void recompute_want(Scanner& s) {
    int want = 0;
    for (auto& [key, name] : s.manual) {
        if (key.size() == 16) want |= kWantMd5;
        if (key.size() == 20) want |= kWantSha1;
    }
    for (auto& p : s.packs) {
        if (p->count(kMd5)) want |= kWantMd5;
        if (p->count(kSha1)) want |= kWantSha1;
    }
    s.want = want;
}

struct HashHit {
    std::wstring name, source;  // source: pack label, empty for hashes.txt
    int kind = -1;
};

// Strongest hash first. Call with sig_lock held (shared is enough).
bool lookup(const Scanner& s, const Digests& d, HashHit& hit) {
    const uint8_t* digests[kHashKinds] = {d.md5, d.sha1, d.sha256};
    const bool have[kHashKinds] = {(d.have & kWantMd5) != 0, (d.have & kWantSha1) != 0, true};
    for (int k = kSha256; k >= kMd5; --k) {
        if (!have[k]) continue;
        auto it = s.manual.find(std::string((const char*)digests[k], kDigestLen[k]));
        if (it != s.manual.end()) {
            hit = {it->second, L"", k};
            return true;
        }
        for (auto& p : s.packs) {
            if (p->find(k, digests[k], hit.name)) {
                hit.source = p->label();
                hit.kind = k;
                return true;
            }
        }
    }
    return false;
}

bool has_extension(const std::wstring& name, const wchar_t* ext) {
    size_t n = wcslen(ext);
    return name.size() > n && _wcsicmp(name.c_str() + name.size() - n, ext) == 0;
}

// Loads every *.vdb in dir. When several packs share a label (an import was redone),
// only the newest counts and the rest are deleted, or renamed aside if another
// process still has them open.
void load_packs(Scanner& s, const std::wstring& dir) {
    std::map<std::wstring, std::unique_ptr<SigPack>> newest;  // by lower-case label
    std::vector<std::wstring> stale;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring path = dir + L"\\" + fd.cFileName;
        if (has_extension(fd.cFileName, L".removed") || has_extension(fd.cFileName, L".vdb.tmp")) {
            DeleteFileW(path.c_str());  // fails harmlessly while still open
            continue;
        }
        if (!has_extension(fd.cFileName, L".vdb")) continue;
        auto pack = SigPack::open(path);
        if (!pack) continue;  // malformed: ignore rather than trust any of it
        auto& slot = newest[lower(pack->label())];
        if (!slot || pack->created() > slot->created()) {
            if (slot) stale.push_back(slot->path());
            slot = std::move(pack);
        } else {
            stale.push_back(path);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    for (auto& [label, pack] : newest) s.packs.push_back(std::move(pack));
    for (auto& path : stale)
        if (!DeleteFileW(path.c_str())) MoveFileExW(path.c_str(), (path + L".removed").c_str(), MOVEFILE_REPLACE_EXISTING);
}

// ---------------------------------------------------------------- scan cache
// Remembers files that scanned clean, keyed by path + size + timestamps, so repeat
// scans skip them. Any change to the signature set or AMSI setting clears it.
constexpr char kCacheMagic[8] = {'V', 'E', 'Y', 'L', 'S', 'C', '0', '1'};
constexpr size_t kCacheMax = 4'000'000;

struct CacheKey {
    uint64_t path_hash, size, write_time, create_time;
    bool operator==(const CacheKey&) const = default;
};
struct CacheKeyHash {
    size_t operator()(const CacheKey& k) const {
        return (size_t)(k.path_hash ^ (k.size * 0x9E3779B97F4A7C15ull) ^ (k.write_time << 1) ^ k.create_time);
    }
};

struct ScanCache {
    std::shared_mutex lock;
    std::unordered_set<CacheKey, CacheKeyHash> clean;
    uint64_t stamp = 0;  // which signature set / settings the entries are valid for
} g_cache;

uint64_t fnv1a_lower(const std::wstring& s) {
    uint64_t h = 1469598103934665603ull;
    for (wchar_t c : s) {
        h ^= (uint64_t)towlower(c);
        h *= 1099511628211ull;
    }
    return h;
}

uint64_t filetime(const FILETIME& t) { return ((uint64_t)t.dwHighDateTime << 32) | t.dwLowDateTime; }

CacheKey cache_key(const std::wstring& path, const WIN32_FILE_ATTRIBUTE_DATA& a) {
    return {fnv1a_lower(path), ((uint64_t)a.nFileSizeHigh << 32) | a.nFileSizeLow, filetime(a.ftLastWriteTime),
            filetime(a.ftCreationTime)};
}

// Changes whenever signatures or AMSI change; a mismatch empties the cache.
// Packs count by their content hash, so this stays cheap with millions of hashes loaded.
uint64_t current_stamp() {
    auto& s = scanner();
    uint64_t h = 0x5645594C ^ (uint64_t)s.manual.size() ^ ((uint64_t)(s.amsi != nullptr) << 63);
    for (auto& [hash, name] : s.manual) h += std::hash<std::string>{}(hash);
    for (auto& p : s.packs) {
        uint64_t id;
        memcpy(&id, p->content_id(), 8);
        h = h * 0x100000001B3ull ^ id;
    }
    return h;
}

void restamp_cache() {
    uint64_t stamp;
    {
        std::shared_lock g(scanner().sig_lock);
        std::lock_guard a(scanner().amsi_lock);
        stamp = current_stamp();
    }
    std::unique_lock g(g_cache.lock);
    if (g_cache.stamp != stamp) {
        g_cache.clean.clear();
        g_cache.stamp = stamp;
    }
}

// ---------------------------------------------------------------- scanning
int scan_one(const std::wstring& p, const WIN32_FILE_ATTRIBUTE_DATA& attr, bool use_cache, VeylScanResult* out) {
    auto& s = scanner();
    uint64_t size = ((uint64_t)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
    if (size > kMaxHashBytes) {
        fill(out, VEYL_SKIPPED, 0, L"", L"File too large");
        return VEYL_OK;
    }

    CacheKey key = cache_key(p, attr);
    if (use_cache) {
        std::shared_lock g(g_cache.lock);
        if (g_cache.clean.count(key)) {
            fill(out, VEYL_CLEAN, 0, L"", L"Unchanged since its last clean scan");
            return VEYL_OK;
        }
    }

    std::wstring ext = extension(p);
    bool is_script = is_script_ext(ext);
    bool is_mz = size >= 64 && starts_with_mz(p);
    bool deep = size > 0 && size <= kMaxHeuristicBytes && (is_script || is_mz);

    if (!deep && !is_mz && is_inert_media(ext)) {
        fill(out, VEYL_CLEAN, 0, L"", L"Media file, not executable");
        return VEYL_OK;
    }

    // Executables and scripts: read once, then hash and analyse the same buffer.
    // MD5 and SHA-1 are only computed when some loaded list has hashes of that kind.
    Bytes data;
    Digests digests;
    int want = s.want;
    if (deep) {
        if (!read_file(p, data, kMaxHeuristicBytes)) {
            fill(out, VEYL_SKIPPED, 0, L"", L"File is locked or unreadable");
            return VEYL_OK;
        }
        if (!hash_buffer(data.data(), data.size(), want, digests)) {
            fill(out, VEYL_SKIPPED, 0, L"", L"Hashing failed");
            return VEYL_OK;
        }
    } else if (hash_file(p, want, digests) != VEYL_OK) {
        fill(out, VEYL_SKIPPED, 0, L"", L"File is locked or unreadable");
        return VEYL_OK;
    }
    memcpy(out->sha256, hex(digests.sha256, 32).c_str(), 65);

    {
        std::shared_lock g(s.sig_lock);
        HashHit hit;
        if (lookup(s, digests, hit)) {
            std::wstring detail = std::wstring(L"Matched a known-bad ") + hash_kind_name(hit.kind) + L" hash";
            if (!hit.source.empty()) detail += L" from the " + hit.source + L" list";
            fill(out, VEYL_MALICIOUS, 100, hit.name.empty() ? L"Blocklisted file" : hit.name, detail);
            return VEYL_OK;
        }
    }

    auto remember_clean = [&] {
        std::unique_lock g(g_cache.lock);
        if (g_cache.clean.size() < kCacheMax) g_cache.clean.insert(key);
    };

    if (!deep) {
        fill(out, VEYL_CLEAN, 0, L"", L"");
        remember_clean();
        return VEYL_OK;
    }

    if (size <= kMaxAmsiBytes && amsi_detects(data, p)) {
        fill(out, VEYL_MALICIOUS, 100, L"Defender:AMSI.Detection", L"Flagged by the Windows Defender engine via AMSI");
        return VEYL_OK;
    }

    Findings f;
    if (is_mz) pe_heuristics(data, f);
    else script_heuristics(data, f);
    if (double_extension(p)) f.add(30, L"Disguised file extension");

    // A valid Authenticode signature is strong evidence of legitimacy. Only pay for
    // the check when something already looks off.
    if (is_mz && f.score >= 25 && has_valid_signature(p)) {
        f.score = std::max(0, f.score - 40);
        f.reasons += L"; Validly signed";
    }

    if (f.score >= kSuspiciousScore) {
        fill(out, VEYL_SUSPICIOUS, f.score, is_mz ? L"Heuristic:Win/SuspiciousPE" : L"Heuristic:Script/Suspicious", f.reasons);
    } else {
        fill(out, VEYL_CLEAN, f.score, L"", f.reasons);
        remember_clean();
    }
    return VEYL_OK;
}

// ---------------------------------------------------------------- directory scans
// One thread walks the tree and queues files; a pool of workers scans them. The
// callback is serialised, so callers never see it run concurrently.
struct Job {
    std::wstring path;
    WIN32_FILE_ATTRIBUTE_DATA attr;
};

struct DirScan {
    VeylScanCallback cb = nullptr;
    void* ctx = nullptr;
    bool use_cache = true;
    std::mutex queue_lock, cb_lock;
    std::condition_variable has_work, has_room;
    std::deque<Job> queue;
    bool done_walking = false;
    std::atomic<bool> cancel{false};
    std::atomic<int> files{0}, threats{0};

    void stop() {
        {
            std::lock_guard g(queue_lock);
            cancel = true;
        }
        has_work.notify_all();
        has_room.notify_all();
    }

    void worker() {
        for (;;) {
            Job job;
            {
                std::unique_lock g(queue_lock);
                has_work.wait(g, [&] { return !queue.empty() || done_walking || cancel; });
                if (cancel || queue.empty()) return;
                job = std::move(queue.front());
                queue.pop_front();
            }
            has_room.notify_one();
            VeylScanResult r;
            memset(&r, 0, sizeof r);
            scan_one(job.path, job.attr, use_cache, &r);
            ++files;
            if (r.verdict == VEYL_MALICIOUS || r.verdict == VEYL_SUSPICIOUS) ++threats;
            if (cb) {
                std::lock_guard g(cb_lock);
                if (!cancel && cb(job.path.c_str(), &r, ctx) == 0) stop();
            }
        }
    }

    void push(Job&& job) {
        std::unique_lock g(queue_lock);
        has_room.wait(g, [&] { return queue.size() < 4096 || cancel; });
        if (cancel) return;
        queue.push_back(std::move(job));
        g.unlock();
        has_work.notify_one();
    }

    void walk(const std::wstring& dir, int depth) {
        if (depth > 64 || cancel) return;
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr,
                                    FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            // Skip junctions and symlinks so we never loop or leave the requested tree.
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            std::wstring full = dir + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                walk(full, depth + 1);
            } else {
                // The listing already has size and times, so workers needn't ask again.
                WIN32_FILE_ATTRIBUTE_DATA a{fd.dwFileAttributes, fd.ftCreationTime, fd.ftLastAccessTime,
                                            fd.ftLastWriteTime, fd.nFileSizeHigh, fd.nFileSizeLow};
                push({std::move(full), a});
            }
        } while (!cancel && FindNextFileW(h, &fd));
        FindClose(h);
    }
};

}  // namespace
}  // namespace veyl

using namespace veyl;

VEYL_API int veyl_scanner_init(const wchar_t* signature_file, int use_amsi) {
    auto& s = scanner();
    {
        std::unique_lock g(s.sig_lock);
        s.manual.clear();
        s.packs.clear();
        if (signature_file) {
            std::ifstream in(signature_file);
            std::string line;
            while (std::getline(in, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line[0] == '#') continue;
                size_t sp = line.find_first_of(" \t");
                std::string key = digest_key(line.substr(0, sp));
                if (key.empty()) continue;
                size_t name_at = sp == std::string::npos ? std::string::npos : line.find_first_not_of(" \t", sp);
                std::string name = name_at == std::string::npos ? "" : line.substr(name_at);
                while (!name.empty() && name.back() == ' ') name.pop_back();
                s.manual[key] = name.empty() ? L"Blocklisted file" : to_wide(name);
            }
            // Signature packs live next to the text list.
            std::wstring dir(signature_file);
            size_t slash = dir.find_last_of(L"\\/");
            load_packs(s, slash == std::wstring::npos ? L"." : dir.substr(0, slash));
        }
        recompute_want(s);
        s.initialised = true;
    }
    {
        std::lock_guard g(s.amsi_lock);
        if (use_amsi && !s.amsi) {
            if (FAILED(AmsiInitialize(L"VEYL", &s.amsi))) s.amsi = nullptr;
        } else if (!use_amsi && s.amsi) {
            AmsiUninitialize(s.amsi);
            s.amsi = nullptr;
        }
    }
    restamp_cache();
    return VEYL_OK;
}

VEYL_API int veyl_scanner_signature_counts(int64_t* md5, int64_t* sha1, int64_t* sha256) {
    auto& s = scanner();
    std::shared_lock g(s.sig_lock);
    int64_t n[kHashKinds]{};
    for (auto& [key, name] : s.manual) n[key.size() == 16 ? kMd5 : key.size() == 20 ? kSha1 : kSha256]++;
    for (auto& p : s.packs)
        for (int k = 0; k < kHashKinds; ++k) n[k] += (int64_t)p->count(k);
    if (md5) *md5 = n[kMd5];
    if (sha1) *sha1 = n[kSha1];
    if (sha256) *sha256 = n[kSha256];
    return VEYL_OK;
}

VEYL_API int veyl_scanner_signature_count(void) {
    int64_t a, b, c;
    veyl_scanner_signature_counts(&a, &b, &c);
    return (int)std::min<int64_t>(a + b + c, INT_MAX);
}

VEYL_API int veyl_scanner_add_signature(const wchar_t* hash_hex, const wchar_t* name) {
    if (!hash_hex) return VEYL_ERR_ARG;
    std::string key = digest_key(to_utf8(hash_hex));
    if (key.empty()) return VEYL_ERR_ARG;
    {
        std::unique_lock g(scanner().sig_lock);
        scanner().manual[key] = name && *name ? name : L"Blocklisted file";
        recompute_want(scanner());
    }
    restamp_cache();
    return VEYL_OK;
}

VEYL_API int veyl_scanner_pack_info(int index, wchar_t label[64], wchar_t path[260], int64_t* hashes,
                                    int64_t* created_unix) {
    auto& s = scanner();
    std::shared_lock g(s.sig_lock);
    if (index < 0 || index >= (int)s.packs.size()) return VEYL_ERR_NOT_FOUND;
    const SigPack& p = *s.packs[index];
    if (label) copy_fixed(p.label(), label, 64);
    if (path) copy_fixed(p.path(), path, 260);
    if (hashes) *hashes = (int64_t)p.total();
    if (created_unix) *created_unix = (int64_t)((p.created() - 116444736000000000ull) / 10000000ull);
    return VEYL_OK;
}

VEYL_API int veyl_scanner_remove_pack(const wchar_t* path) {
    if (!path) return VEYL_ERR_ARG;
    auto& s = scanner();
    std::wstring target(path);
    {
        std::unique_lock g(s.sig_lock);
        auto it = std::find_if(s.packs.begin(), s.packs.end(),
                               [&](auto& p) { return _wcsicmp(p->path().c_str(), target.c_str()) == 0; });
        if (it == s.packs.end()) return VEYL_ERR_NOT_FOUND;
        s.packs.erase(it);  // unmaps it
        recompute_want(s);
    }
    restamp_cache();
    // Another user's VEYL may still have it mapped; then park it under a name the
    // loader ignores and deletes later.
    if (!DeleteFileW(target.c_str()) &&
        !MoveFileExW(target.c_str(), (target + L".removed").c_str(), MOVEFILE_REPLACE_EXISTING))
        return VEYL_ERR_IO;
    return VEYL_OK;
}

VEYL_API void veyl_scanner_shutdown(void) {
    auto& s = scanner();
    {
        std::lock_guard g(s.amsi_lock);
        if (s.amsi) AmsiUninitialize(s.amsi);
        s.amsi = nullptr;
    }
    std::unique_lock g(s.sig_lock);
    s.manual.clear();
    s.packs.clear();
    s.want = 0;
    s.initialised = false;
}

VEYL_API int veyl_scan_file_ex(const wchar_t* path, int flags, VeylScanResult* out) {
    if (!path || !out) return VEYL_ERR_ARG;
    memset(out, 0, sizeof *out);
    if (!scanner().initialised) return VEYL_ERR_STATE;
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &attr)) {
        fill(out, VEYL_SKIPPED, 0, L"", L"File not accessible");
        return VEYL_OK;
    }
    return scan_one(path, attr, !(flags & VEYL_SCAN_NO_CACHE), out);
}

VEYL_API int veyl_scan_file(const wchar_t* path, VeylScanResult* out) { return veyl_scan_file_ex(path, 0, out); }

VEYL_API int veyl_scan_directory_ex(const wchar_t* path, int flags, VeylScanCallback cb, void* ctx, int* out_files,
                                    int* out_threats) {
    if (!path) return VEYL_ERR_ARG;
    if (!scanner().initialised) return VEYL_ERR_STATE;
    std::wstring root(path);
    while (root.size() > 3 && (root.back() == L'\\' || root.back() == L'/')) root.pop_back();
    if (root.size() == 3 && root.back() == L'\\') root.pop_back();  // "C:\" -> "C:"

    DirScan scan;
    scan.cb = cb;
    scan.ctx = ctx;
    scan.use_cache = !(flags & VEYL_SCAN_NO_CACHE);
    // Disk-bound work: a few threads keep an SSD busy without thrashing a hard disk.
    unsigned n = std::clamp(std::thread::hardware_concurrency(), 2u, 8u);
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < n; ++i) workers.emplace_back([&] { scan.worker(); });

    scan.walk(root, 0);
    {
        std::lock_guard g(scan.queue_lock);
        scan.done_walking = true;
    }
    scan.has_work.notify_all();
    for (auto& t : workers) t.join();

    if (out_files) *out_files = scan.files;
    if (out_threats) *out_threats = scan.threats;
    return VEYL_OK;
}

VEYL_API int veyl_scan_directory(const wchar_t* path, VeylScanCallback cb, void* ctx, int* out_files, int* out_threats) {
    return veyl_scan_directory_ex(path, 0, cb, ctx, out_files, out_threats);
}

// ---------------------------------------------------------------- cache persistence
VEYL_API int veyl_scan_cache_load(const wchar_t* path) {
    if (!path) return VEYL_ERR_ARG;
    Bytes b;
    if (!read_file(path, b, 256ull << 20)) return VEYL_ERR_NOT_FOUND;
    if (b.size() < 24 || memcmp(b.data(), kCacheMagic, 8) != 0) return VEYL_ERR_FORMAT;
    uint64_t stamp, count;
    memcpy(&stamp, b.data() + 8, 8);
    memcpy(&count, b.data() + 16, 8);
    if (count > kCacheMax || b.size() != 24 + count * sizeof(CacheKey)) return VEYL_ERR_FORMAT;
    std::unique_lock g(g_cache.lock);
    if (stamp != g_cache.stamp) return VEYL_OK;  // signatures changed since it was saved; start fresh
    g_cache.clean.reserve((size_t)count);
    for (uint64_t i = 0; i < count; ++i) {
        CacheKey k;
        memcpy(&k, b.data() + 24 + i * sizeof(CacheKey), sizeof k);
        g_cache.clean.insert(k);
    }
    return VEYL_OK;
}

VEYL_API int veyl_scan_cache_save(const wchar_t* path) {
    if (!path) return VEYL_ERR_ARG;
    Bytes b(kCacheMagic, kCacheMagic + 8);
    {
        std::shared_lock g(g_cache.lock);
        uint64_t count = g_cache.clean.size();
        b.reserve(24 + count * sizeof(CacheKey));
        b.insert(b.end(), (uint8_t*)&g_cache.stamp, (uint8_t*)&g_cache.stamp + 8);
        b.insert(b.end(), (uint8_t*)&count, (uint8_t*)&count + 8);
        for (const auto& k : g_cache.clean) b.insert(b.end(), (const uint8_t*)&k, (const uint8_t*)&k + sizeof k);
    }
    bool ok = write_file_atomic(path, b.data(), b.size());
    DeleteFileW((std::wstring(path) + L".bak").c_str());
    return ok ? VEYL_OK : VEYL_ERR_IO;
}

VEYL_API void veyl_scan_cache_clear(void) {
    std::unique_lock g(g_cache.lock);
    g_cache.clean.clear();
}

VEYL_API int veyl_scan_cache_count(void) {
    std::shared_lock g(g_cache.lock);
    return (int)g_cache.clean.size();
}
