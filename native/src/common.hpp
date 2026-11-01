#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "veyl_core.h"

namespace veyl {

using Bytes = std::vector<uint8_t>;

// std::vector whose storage is wiped on destruction. Used for keys and plaintext.
struct SecureBytes : Bytes {
    using Bytes::Bytes;
    SecureBytes(const SecureBytes&) = default;
    SecureBytes(SecureBytes&&) = default;
    SecureBytes& operator=(const SecureBytes&) = default;
    SecureBytes& operator=(SecureBytes&&) = default;
    ~SecureBytes() { wipe(); }
    void wipe() {
        if (!empty()) SecureZeroMemory(data(), size());
    }
};

inline void wipe(std::string& s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.size());
    s.clear();
}

std::string to_utf8(const wchar_t* s, int len = -1);
std::wstring to_wide(const std::string& s);

// Copies src into a caller buffer. On short buffer returns VEYL_ERR_BUFFER and
// writes the required size (including terminator) to *len.
int copy_out(const std::wstring& src, wchar_t* buf, int* len);
void copy_fixed(const std::wstring& src, wchar_t* buf, size_t cap);

bool read_file(const std::wstring& path, Bytes& out, uint64_t max_bytes = UINT64_MAX);
// Writes via a temp file and an atomic replace.
bool write_file_atomic(const std::wstring& path, const uint8_t* data, size_t size);

int64_t unix_now();
std::wstring new_uuid();

// ---- crypto (crypto.cpp)
bool random_bytes(uint8_t* out, size_t n);
bool sha256(const uint8_t* data, size_t n, uint8_t out[32]);
std::string hex(const uint8_t* data, size_t n);
// Decodes 2*n hex digits into out. False on any non-hex character.
bool unhex(const char* s, size_t n, uint8_t* out);

// MD5, SHA-1 and SHA-256 of one input, computed in a single pass. SHA-256 is always
// computed; the other two only when asked for (they cost time on every scanned file).
enum : int { kWantMd5 = 1, kWantSha1 = 2 };
struct Digests {
    uint8_t md5[16]{}, sha1[20]{}, sha256[32]{};
    int have = 0;  // kWant* bits that were filled in
};
bool hash_buffer(const uint8_t* data, size_t n, int want, Digests& out);
int hash_file(const std::wstring& path, int want, Digests& out);  // VEYL_* status
bool pbkdf2_sha256(const uint8_t* pw, size_t pw_len, const uint8_t* salt, size_t salt_len,
                   uint32_t iterations, uint8_t* out, size_t out_len);
bool aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad,
                     size_t aad_len, const uint8_t* pt, size_t pt_len, Bytes& ct, uint8_t tag[16]);
// Returns false if authentication fails.
bool aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad,
                     size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t tag[16],
                     SecureBytes& pt);

}  // namespace veyl
