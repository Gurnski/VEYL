// Thin wrappers over Windows CNG (bcrypt). No third-party crypto.
#include "common.hpp"

#include <bcrypt.h>

#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

namespace veyl {

namespace {

struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    AlgHandle(LPCWSTR alg, ULONG flags) { BCryptOpenAlgorithmProvider(&h, alg, nullptr, flags); }
    ~AlgHandle() {
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
};

BCRYPT_ALG_HANDLE hmac_sha256() {
    static AlgHandle alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    return alg.h;
}

BCRYPT_ALG_HANDLE aes_gcm() {
    static AlgHandle alg(BCRYPT_AES_ALGORITHM, 0);
    static bool configured = alg.h && BCRYPT_SUCCESS(BCryptSetProperty(
        alg.h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));
    return configured ? alg.h : nullptr;
}

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() {
        if (h) BCryptDestroyKey(h);
    }
};

}  // namespace

bool random_bytes(uint8_t* out, size_t n) {
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool sha256(const uint8_t* data, size_t n, uint8_t out[32]) {
    return BCRYPT_SUCCESS(
        BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, (PUCHAR)data, (ULONG)n, out, 32));
}

std::string hex(const uint8_t* data, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        s[i * 2] = digits[data[i] >> 4];
        s[i * 2 + 1] = digits[data[i] & 0xF];
    }
    return s;
}

bool unhex(const char* s, size_t n, uint8_t* out) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; ++i) {
        int hi = nibble(s[i * 2]), lo = nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

namespace {

// Up to three CNG hash objects fed from the same bytes.
struct MultiHash {
    BCRYPT_HASH_HANDLE h[3]{};
    bool ok = true;

    explicit MultiHash(int want) {
        ok = BCRYPT_SUCCESS(BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &h[0], nullptr, 0, nullptr, 0, 0));
        if (ok && (want & kWantMd5))
            ok = BCRYPT_SUCCESS(BCryptCreateHash(BCRYPT_MD5_ALG_HANDLE, &h[1], nullptr, 0, nullptr, 0, 0));
        if (ok && (want & kWantSha1))
            ok = BCRYPT_SUCCESS(BCryptCreateHash(BCRYPT_SHA1_ALG_HANDLE, &h[2], nullptr, 0, nullptr, 0, 0));
    }
    ~MultiHash() {
        for (auto x : h)
            if (x) BCryptDestroyHash(x);
    }
    bool update(const uint8_t* p, ULONG n) {
        for (auto x : h)
            if (ok && x) ok = BCRYPT_SUCCESS(BCryptHashData(x, (PUCHAR)p, n, 0));
        return ok;
    }
    bool finish(Digests& out) {
        out.have = 0;
        if (!ok || !BCRYPT_SUCCESS(BCryptFinishHash(h[0], out.sha256, 32, 0))) return false;
        if (h[1]) {
            if (!BCRYPT_SUCCESS(BCryptFinishHash(h[1], out.md5, 16, 0))) return false;
            out.have |= kWantMd5;
        }
        if (h[2]) {
            if (!BCRYPT_SUCCESS(BCryptFinishHash(h[2], out.sha1, 20, 0))) return false;
            out.have |= kWantSha1;
        }
        return true;
    }
};

}  // namespace

bool hash_buffer(const uint8_t* data, size_t n, int want, Digests& out) {
    MultiHash mh(want);
    for (size_t done = 0; done < n;) {
        ULONG chunk = (ULONG)std::min<size_t>(n - done, 1u << 30);
        if (!mh.update(data + done, chunk)) return false;
        done += chunk;
    }
    return mh.finish(out);
}

int hash_file(const std::wstring& path, int want, Digests& out) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return VEYL_ERR_IO;
    MultiHash mh(want);
    std::vector<uint8_t> chunk(1 << 20);
    int rc = mh.ok ? VEYL_OK : VEYL_ERR_CRYPTO;
    while (rc == VEYL_OK) {
        DWORD got = 0;
        if (!ReadFile(f, chunk.data(), (DWORD)chunk.size(), &got, nullptr)) rc = VEYL_ERR_IO;
        else if (got == 0) break;
        else if (!mh.update(chunk.data(), got)) rc = VEYL_ERR_CRYPTO;
    }
    CloseHandle(f);
    if (rc == VEYL_OK && !mh.finish(out)) rc = VEYL_ERR_CRYPTO;
    return rc;
}

bool pbkdf2_sha256(const uint8_t* pw, size_t pw_len, const uint8_t* salt, size_t salt_len,
                   uint32_t iterations, uint8_t* out, size_t out_len) {
    BCRYPT_ALG_HANDLE prf = hmac_sha256();
    if (!prf) return false;
    // CNG rejects a NULL password pointer even with length 0.
    static const uint8_t empty = 0;
    return BCRYPT_SUCCESS(BCryptDeriveKeyPBKDF2(prf, (PUCHAR)(pw_len ? pw : &empty), (ULONG)pw_len,
                                                (PUCHAR)salt, (ULONG)salt_len, iterations, out,
                                                (ULONG)out_len, 0));
}

static bool make_key(const uint8_t key[32], KeyHandle& k) {
    BCRYPT_ALG_HANDLE alg = aes_gcm();
    if (!alg) return false;
    return BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &k.h, nullptr, 0, (PUCHAR)key, 32, 0));
}

bool aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad,
                     size_t aad_len, const uint8_t* pt, size_t pt_len, Bytes& ct, uint8_t tag[16]) {
    KeyHandle k;
    if (!make_key(key, k)) return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = tag;
    info.cbTag = 16;

    ct.resize(pt_len);
    ULONG written = 0;
    NTSTATUS st = BCryptEncrypt(k.h, (PUCHAR)pt, (ULONG)pt_len, &info, nullptr, 0,
                                ct.empty() ? nullptr : ct.data(), (ULONG)ct.size(), &written, 0);
    return BCRYPT_SUCCESS(st) && written == pt_len;
}

bool aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad,
                     size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t tag[16],
                     SecureBytes& pt) {
    KeyHandle k;
    if (!make_key(key, k)) return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = 16;

    pt.resize(ct_len);
    ULONG written = 0;
    NTSTATUS st = BCryptDecrypt(k.h, (PUCHAR)ct, (ULONG)ct_len, &info, nullptr, 0,
                                pt.empty() ? nullptr : pt.data(), (ULONG)pt.size(), &written, 0);
    if (!BCRYPT_SUCCESS(st) || written != ct_len) {
        pt.wipe();
        pt.clear();
        return false;
    }
    return true;
}

}  // namespace veyl
