// Encrypted password vault.
//
// Format v2 (little endian). The payload is encrypted with a random 256-bit vault
// key (DEK). The DEK is stored twice, each copy wrapped with AES-256-GCM under a key
// derived (PBKDF2-HMAC-SHA256) from one secret: the master password, and optionally a
// recovery key. Either secret opens the vault; changing one re-wraps only its slot.
//
//   header (184 bytes, all of it is AAD for the payload)
//     char[8]  magic "VEYLVLT\0"
//     u16      format version (2)
//     u16      kdf id (1 = PBKDF2-HMAC-SHA256)
//     slot     password: u32 iterations, u8[16] salt, u8[12] nonce, u8[32] wrapped DEK, u8[16] tag
//     slot     recovery: same layout; iterations == 0 means no recovery key
//     u8[12]   payload nonce (fresh on every save)
//   ciphertext (AES-256-GCM of the payload under the DEK)
//   u8[16]   payload tag
//
// Format v1 (read only, migrated to v2 on open): 44-byte header with the key derived
// straight from the password: magic, u16 version 1, u16 kdf, u32 iterations, salt[16], nonce[12].
//
// Payload: u32 payload version, u32 entry count, then per entry six length-prefixed
// UTF-8 strings (id, title, username, password, url, notes) and i64 created/modified.
#include "common.hpp"

#include <mutex>

namespace veyl {

bool clipboard_set_secret(const std::wstring& text, int clear_after_sec);

namespace {

constexpr char kMagic[8] = {'V', 'E', 'Y', 'L', 'V', 'L', 'T', '\0'};
constexpr uint16_t kKdfPbkdf2 = 1;
constexpr uint32_t kIterations = 600000;
constexpr uint32_t kRecoveryIterations = 100000;  // recovery keys carry 160 random bits
constexpr uint32_t kMinIterations = 100000;
constexpr uint32_t kMaxIterations = 50000000;
constexpr size_t kHeaderV1 = 44;
constexpr size_t kSlotSize = 4 + 16 + 12 + 32 + 16;
constexpr size_t kHeaderV2 = 8 + 2 + 2 + kSlotSize * 2 + 12;
constexpr uint32_t kPayloadVersion = 1;
constexpr size_t kMaxField = 1 << 20;

// Crockford base32: no I, L, O or U, so keys are easy to read aloud and retype.
constexpr char kBase32[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
constexpr size_t kRecoveryBytes = 20;  // 160 bits -> 32 characters

struct Entry {
    std::string fields[6];  // indexed by VeylField
    int64_t created = 0;
    int64_t modified = 0;
    Entry() = default;
    Entry(const Entry&) = default;
    Entry& operator=(const Entry&) = default;
    ~Entry() {
        for (auto& f : fields) wipe(f);
    }
};

struct Slot {
    uint32_t iterations = 0;  // 0 = empty
    uint8_t salt[16]{};
    uint8_t nonce[12]{};
    uint8_t wrapped[32]{};
    uint8_t tag[16]{};

    void write(uint8_t* p) const {
        memcpy(p, &iterations, 4);
        memcpy(p + 4, salt, 16);
        memcpy(p + 20, nonce, 12);
        memcpy(p + 32, wrapped, 32);
        memcpy(p + 64, tag, 16);
    }
    void read(const uint8_t* p) {
        memcpy(&iterations, p, 4);
        memcpy(salt, p + 4, 16);
        memcpy(nonce, p + 20, 12);
        memcpy(wrapped, p + 32, 32);
        memcpy(tag, p + 64, 16);
    }
};

// Wrap AAD binds each wrapped key to its slot, so slots can't be swapped.
void slot_aad(uint8_t id, uint8_t out[10]) {
    memcpy(out, kMagic, 8);
    out[8] = 2;
    out[9] = id;
}

bool derive(const uint8_t* secret, size_t len, const uint8_t salt[16], uint32_t iterations, uint8_t key[32]) {
    return pbkdf2_sha256(secret, len, salt, 16, iterations, key, 32);
}

bool derive_pw(std::wstring_view pw, const uint8_t salt[16], uint32_t iterations, uint8_t key[32]) {
    std::string utf8 = to_utf8(pw.data(), (int)pw.size());
    bool ok = derive((const uint8_t*)utf8.data(), utf8.size(), salt, iterations, key);
    wipe(utf8);
    return ok;
}

// Fills the slot with the DEK wrapped under a key derived from `secret`.
bool seal_slot(Slot& s, uint8_t id, const uint8_t* secret, size_t len, uint32_t iterations, const uint8_t dek[32]) {
    uint8_t kek[32];
    s.iterations = iterations;
    bool ok = random_bytes(s.salt, 16) && random_bytes(s.nonce, 12) && derive(secret, len, s.salt, iterations, kek);
    if (ok) {
        uint8_t aad[10];
        slot_aad(id, aad);
        Bytes ct;
        ok = aes_gcm_encrypt(kek, s.nonce, aad, 10, dek, 32, ct, s.tag);
        if (ok) memcpy(s.wrapped, ct.data(), 32);
    }
    SecureZeroMemory(kek, 32);
    return ok;
}

// Recovers the DEK from a slot; false if the secret is wrong.
bool open_slot(const Slot& s, uint8_t id, const uint8_t* secret, size_t len, uint8_t dek[32]) {
    if (s.iterations < kMinIterations / 10 || s.iterations > kMaxIterations) return false;
    uint8_t kek[32];
    bool ok = derive(secret, len, s.salt, s.iterations, kek);
    if (ok) {
        uint8_t aad[10];
        slot_aad(id, aad);
        SecureBytes pt;
        ok = aes_gcm_decrypt(kek, s.nonce, aad, 10, s.wrapped, 32, s.tag, pt) && pt.size() == 32;
        if (ok) memcpy(dek, pt.data(), 32);
    }
    SecureZeroMemory(kek, 32);
    return ok;
}

// "abcd-efgh ..." -> "ABCDEFGH...", mapping look-alikes. Empty string if invalid.
std::string normalize_recovery(const wchar_t* in, int len) {
    std::string out;
    for (int i = 0; i < len; ++i) {
        wchar_t c = towupper(in[i]);
        if (c == L'-' || c == L' ') continue;
        if (c == L'O') c = L'0';
        if (c == L'I' || c == L'L') c = L'1';
        if (c > 127 || !strchr(kBase32, (char)c) || c == 0) {
            wipe(out);
            return {};
        }
        out += (char)c;
    }
    if (out.size() != 32) wipe(out);
    return out;
}

std::string make_recovery(const uint8_t bytes[kRecoveryBytes]) {
    std::string s;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < kRecoveryBytes; ++i) {
        buf = (buf << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
            s += kBase32[(buf >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    return s;  // 160 bits = exactly 32 characters
}

// ---- payload (de)serialisation
void put_u32(SecureBytes& b, uint32_t v) { b.insert(b.end(), (uint8_t*)&v, (uint8_t*)&v + 4); }
void put_i64(SecureBytes& b, int64_t v) { b.insert(b.end(), (uint8_t*)&v, (uint8_t*)&v + 8); }
void put_str(SecureBytes& b, const std::string& s) {
    put_u32(b, (uint32_t)s.size());
    b.insert(b.end(), s.begin(), s.end());
}

struct Reader {
    const uint8_t* p;
    size_t left;
    bool ok = true;
    template <typename T>
    T num() {
        T v{};
        if (left < sizeof(T)) { ok = false; return v; }
        memcpy(&v, p, sizeof(T));
        p += sizeof(T);
        left -= sizeof(T);
        return v;
    }
    std::string str() {
        uint32_t n = num<uint32_t>();
        if (!ok || n > left || n > kMaxField) { ok = false; return {}; }
        std::string s((const char*)p, n);
        p += n;
        left -= n;
        return s;
    }
};

}  // namespace
}  // namespace veyl

using namespace veyl;

struct VeylVault {
    std::wstring path;
    Slot pw_slot, rec_slot;
    uint8_t dek[32]{};
    std::vector<Entry> entries;
    std::mutex lock;

    ~VeylVault() { SecureZeroMemory(dek, sizeof dek); }

    int find(const wchar_t* id) const {
        std::string want = to_utf8(id);
        for (size_t i = 0; i < entries.size(); ++i)
            if (entries[i].fields[VEYL_FIELD_ID] == want) return (int)i;
        return -1;
    }

    void write_header(uint8_t* h, const uint8_t nonce[12]) const {
        uint16_t ver = 2;
        memcpy(h, kMagic, 8);
        memcpy(h + 8, &ver, 2);
        memcpy(h + 10, &kKdfPbkdf2, 2);
        pw_slot.write(h + 12);
        rec_slot.write(h + 12 + kSlotSize);
        memcpy(h + 12 + kSlotSize * 2, nonce, 12);
    }
};

static int vault_save_locked(VeylVault* v) {
    SecureBytes payload;
    put_u32(payload, kPayloadVersion);
    put_u32(payload, (uint32_t)v->entries.size());
    for (const auto& e : v->entries) {
        for (const auto& f : e.fields) put_str(payload, f);
        put_i64(payload, e.created);
        put_i64(payload, e.modified);
    }

    uint8_t nonce[12];
    if (!random_bytes(nonce, 12)) return VEYL_ERR_CRYPTO;
    uint8_t hdr[kHeaderV2];
    v->write_header(hdr, nonce);

    Bytes ct;
    uint8_t tag[16];
    if (!aes_gcm_encrypt(v->dek, nonce, hdr, kHeaderV2, payload.data(), payload.size(), ct, tag)) return VEYL_ERR_CRYPTO;

    Bytes file(hdr, hdr + kHeaderV2);
    file.insert(file.end(), ct.begin(), ct.end());
    file.insert(file.end(), tag, tag + 16);
    return write_file_atomic(v->path, file.data(), file.size()) ? VEYL_OK : VEYL_ERR_IO;
}

static int parse_payload(VeylVault* v, const SecureBytes& payload) {
    Reader r{payload.data(), payload.size()};
    uint32_t pver = r.num<uint32_t>();
    uint32_t count = r.num<uint32_t>();
    if (!r.ok || pver != kPayloadVersion || count > 1000000) return VEYL_ERR_FORMAT;
    v->entries.reserve(count);
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        Entry e;
        for (auto& f : e.fields) f = r.str();
        e.created = r.num<int64_t>();
        e.modified = r.num<int64_t>();
        v->entries.push_back(e);
    }
    return r.ok ? VEYL_OK : VEYL_ERR_FORMAT;
}

static int seal_password(VeylVault* v, std::wstring_view pw) {
    std::string utf8 = to_utf8(pw.data(), (int)pw.size());
    bool ok = seal_slot(v->pw_slot, 1, (const uint8_t*)utf8.data(), utf8.size(), kIterations, v->dek);
    wipe(utf8);
    return ok ? VEYL_OK : VEYL_ERR_CRYPTO;
}

// Opens a v1 file with the password and converts it to v2 in memory.
static int open_v1(VeylVault* v, const Bytes& file, std::wstring_view pw) {
    if (file.size() < kHeaderV1 + 16) return VEYL_ERR_FORMAT;
    uint16_t kdf;
    uint32_t iterations;
    memcpy(&kdf, file.data() + 10, 2);
    memcpy(&iterations, file.data() + 12, 4);
    if (kdf != kKdfPbkdf2 || iterations < kMinIterations || iterations > kMaxIterations) return VEYL_ERR_FORMAT;

    uint8_t key[32];
    if (!derive_pw(pw, file.data() + 16, iterations, key)) return VEYL_ERR_CRYPTO;
    SecureBytes payload;
    bool ok = aes_gcm_decrypt(key, file.data() + 32, file.data(), kHeaderV1, file.data() + kHeaderV1,
                              file.size() - kHeaderV1 - 16, file.data() + file.size() - 16, payload);
    SecureZeroMemory(key, 32);
    if (!ok) return VEYL_ERR_AUTH;

    int rc = parse_payload(v, payload);
    if (rc != VEYL_OK) return rc;
    if (!random_bytes(v->dek, 32)) return VEYL_ERR_CRYPTO;
    return seal_password(v, pw);
}

// Opens a v2 file with a secret for the given slot (1 = password, 2 = recovery).
static int open_v2(VeylVault* v, const Bytes& file, uint8_t slot, const uint8_t* secret, size_t len) {
    if (file.size() < kHeaderV2 + 16) return VEYL_ERR_FORMAT;
    uint16_t kdf;
    memcpy(&kdf, file.data() + 10, 2);
    if (kdf != kKdfPbkdf2) return VEYL_ERR_FORMAT;
    v->pw_slot.read(file.data() + 12);
    v->rec_slot.read(file.data() + 12 + kSlotSize);
    const Slot& s = slot == 1 ? v->pw_slot : v->rec_slot;
    if (s.iterations == 0) return VEYL_ERR_STATE;  // no recovery key set up
    if (!open_slot(s, slot, secret, len, v->dek)) return VEYL_ERR_AUTH;

    SecureBytes payload;
    const uint8_t* nonce = file.data() + 12 + kSlotSize * 2;
    if (!aes_gcm_decrypt(v->dek, nonce, file.data(), kHeaderV2, file.data() + kHeaderV2, file.size() - kHeaderV2 - 16,
                         file.data() + file.size() - 16, payload))
        return VEYL_ERR_AUTH;  // header or payload tampered with
    return parse_payload(v, payload);
}

static uint16_t file_version(const Bytes& file) {
    if (file.size() < 12 || memcmp(file.data(), kMagic, 8) != 0) return 0;
    uint16_t ver;
    memcpy(&ver, file.data() + 8, 2);
    return ver;
}

VEYL_API int veyl_vault_create(const wchar_t* path, const wchar_t* pw, int pw_len, VeylVault** out) {
    if (!path || !pw || pw_len <= 0 || !out) return VEYL_ERR_ARG;
    *out = nullptr;
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return VEYL_ERR_EXISTS;

    auto v = new VeylVault();
    v->path = path;
    int rc = random_bytes(v->dek, 32) ? seal_password(v, {pw, (size_t)pw_len}) : VEYL_ERR_CRYPTO;
    if (rc == VEYL_OK) rc = vault_save_locked(v);
    if (rc != VEYL_OK) {
        delete v;
        return rc;
    }
    *out = v;
    return VEYL_OK;
}

VEYL_API int veyl_vault_open(const wchar_t* path, const wchar_t* pw, int pw_len, VeylVault** out) {
    if (!path || !pw || pw_len <= 0 || !out) return VEYL_ERR_ARG;
    *out = nullptr;

    Bytes file;
    if (!read_file(path, file, 256ull << 20)) return VEYL_ERR_IO;

    auto v = new VeylVault();
    v->path = path;
    int rc;
    switch (file_version(file)) {
        case 1:
            rc = open_v1(v, file, {pw, (size_t)pw_len});
            if (rc == VEYL_OK) rc = vault_save_locked(v);  // migrate; the v1 file stays as .bak
            break;
        case 2: {
            std::string utf8 = to_utf8(pw, pw_len);
            rc = open_v2(v, file, 1, (const uint8_t*)utf8.data(), utf8.size());
            wipe(utf8);
            break;
        }
        default:
            rc = VEYL_ERR_FORMAT;
    }
    if (rc != VEYL_OK) {
        delete v;
        return rc;
    }
    *out = v;
    return VEYL_OK;
}

VEYL_API int veyl_vault_open_recovery(const wchar_t* path, const wchar_t* key, int key_len, VeylVault** out) {
    if (!path || !key || key_len <= 0 || !out) return VEYL_ERR_ARG;
    *out = nullptr;
    std::string norm = normalize_recovery(key, key_len);
    if (norm.empty()) return VEYL_ERR_AUTH;

    Bytes file;
    if (!read_file(path, file, 256ull << 20)) return VEYL_ERR_IO;
    if (file_version(file) != 2) return VEYL_ERR_STATE;  // v1 vaults never had a recovery key

    auto v = new VeylVault();
    v->path = path;
    int rc = open_v2(v, file, 2, (const uint8_t*)norm.data(), norm.size());
    wipe(norm);
    if (rc != VEYL_OK) {
        delete v;
        return rc;
    }
    *out = v;
    return VEYL_OK;
}

VEYL_API int veyl_vault_set_recovery(VeylVault* v, wchar_t out_key[40]) {
    if (!v || !out_key) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    uint8_t raw[kRecoveryBytes];
    if (!random_bytes(raw, sizeof raw)) return VEYL_ERR_CRYPTO;
    std::string key = make_recovery(raw);
    SecureZeroMemory(raw, sizeof raw);

    Slot old = v->rec_slot;
    int rc = seal_slot(v->rec_slot, 2, (const uint8_t*)key.data(), key.size(), kRecoveryIterations, v->dek)
                 ? vault_save_locked(v)
                 : VEYL_ERR_CRYPTO;
    if (rc == VEYL_OK) {
        // XXXX-XXXX-... (8 groups of 4)
        std::wstring display;
        for (size_t i = 0; i < key.size(); ++i) {
            if (i && i % 4 == 0) display += L'-';
            display += (wchar_t)key[i];
        }
        copy_fixed(display, out_key, 40);
        SecureZeroMemory(display.data(), display.size() * sizeof(wchar_t));
    } else {
        v->rec_slot = old;
    }
    wipe(key);
    return rc;
}

VEYL_API int veyl_vault_has_recovery(VeylVault* v) {
    if (!v) return 0;
    std::lock_guard g(v->lock);
    return v->rec_slot.iterations != 0;
}

VEYL_API int veyl_vault_save(VeylVault* v) {
    if (!v) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    return vault_save_locked(v);
}

VEYL_API int veyl_vault_change_password(VeylVault* v, const wchar_t* new_pw, int new_pw_len) {
    if (!v || !new_pw || new_pw_len <= 0) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    Slot old = v->pw_slot;
    int rc = seal_password(v, {new_pw, (size_t)new_pw_len});
    if (rc == VEYL_OK) rc = vault_save_locked(v);
    if (rc != VEYL_OK) v->pw_slot = old;  // keep memory in step with the file
    return rc;
}

VEYL_API void veyl_vault_close(VeylVault* v) { delete v; }

VEYL_API int veyl_vault_count(VeylVault* v) {
    if (!v) return 0;
    std::lock_guard g(v->lock);
    return (int)v->entries.size();
}

VEYL_API int veyl_vault_get_field(VeylVault* v, int index, int field, wchar_t* buf, int* len) {
    if (!v || field < VEYL_FIELD_ID || field > VEYL_FIELD_NOTES) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    if (index < 0 || index >= (int)v->entries.size()) return VEYL_ERR_NOT_FOUND;
    return copy_out(to_wide(v->entries[index].fields[field]), buf, len);
}

VEYL_API int veyl_vault_get_times(VeylVault* v, int index, int64_t* created, int64_t* modified) {
    if (!v) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    if (index < 0 || index >= (int)v->entries.size()) return VEYL_ERR_NOT_FOUND;
    if (created) *created = v->entries[index].created;
    if (modified) *modified = v->entries[index].modified;
    return VEYL_OK;
}

VEYL_API int veyl_vault_add(VeylVault* v, const wchar_t* title, const wchar_t* username,
                            const wchar_t* pw, int pw_len, const wchar_t* url,
                            const wchar_t* notes, wchar_t out_id[37]) {
    if (!v || !title || !pw || pw_len < 0) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    Entry e;
    std::wstring id = new_uuid();
    e.fields[VEYL_FIELD_ID] = to_utf8(id.c_str());
    e.fields[VEYL_FIELD_TITLE] = to_utf8(title);
    e.fields[VEYL_FIELD_USERNAME] = to_utf8(username);
    e.fields[VEYL_FIELD_PASSWORD] = to_utf8(pw, pw_len);
    e.fields[VEYL_FIELD_URL] = to_utf8(url);
    e.fields[VEYL_FIELD_NOTES] = to_utf8(notes);
    e.created = e.modified = unix_now();
    v->entries.push_back(e);
    if (out_id) copy_fixed(id, out_id, 37);
    return VEYL_OK;
}

VEYL_API int veyl_vault_update(VeylVault* v, const wchar_t* id, const wchar_t* title,
                               const wchar_t* username, const wchar_t* pw, int pw_len,
                               const wchar_t* url, const wchar_t* notes) {
    if (!v || !id || !title) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    int i = v->find(id);
    if (i < 0) return VEYL_ERR_NOT_FOUND;
    Entry& e = v->entries[i];
    e.fields[VEYL_FIELD_TITLE] = to_utf8(title);
    e.fields[VEYL_FIELD_USERNAME] = to_utf8(username);
    if (pw) {
        wipe(e.fields[VEYL_FIELD_PASSWORD]);
        e.fields[VEYL_FIELD_PASSWORD] = to_utf8(pw, pw_len);
    }
    e.fields[VEYL_FIELD_URL] = to_utf8(url);
    e.fields[VEYL_FIELD_NOTES] = to_utf8(notes);
    e.modified = unix_now();
    return VEYL_OK;
}

VEYL_API int veyl_vault_delete(VeylVault* v, const wchar_t* id) {
    if (!v || !id) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    int i = v->find(id);
    if (i < 0) return VEYL_ERR_NOT_FOUND;
    v->entries.erase(v->entries.begin() + i);
    return VEYL_OK;
}

VEYL_API int veyl_vault_copy_password(VeylVault* v, const wchar_t* id, int clear_after_sec) {
    if (!v || !id) return VEYL_ERR_ARG;
    std::wstring pw;
    {
        std::lock_guard g(v->lock);
        int i = v->find(id);
        if (i < 0) return VEYL_ERR_NOT_FOUND;
        pw = to_wide(v->entries[i].fields[VEYL_FIELD_PASSWORD]);
    }
    bool ok = clipboard_set_secret(pw, clear_after_sec);
    SecureZeroMemory(pw.data(), pw.size() * sizeof(wchar_t));
    return ok ? VEYL_OK : VEYL_ERR_IO;
}

VEYL_API int veyl_vault_reveal_password(VeylVault* v, const wchar_t* id, wchar_t* buf, int* len) {
    if (!v || !id || !len) return VEYL_ERR_ARG;
    std::lock_guard g(v->lock);
    int i = v->find(id);
    if (i < 0) return VEYL_ERR_NOT_FOUND;
    std::wstring pw = to_wide(v->entries[i].fields[VEYL_FIELD_PASSWORD]);
    int rc = copy_out(pw, buf, len);
    SecureZeroMemory(pw.data(), pw.size() * sizeof(wchar_t));
    return rc;
}
