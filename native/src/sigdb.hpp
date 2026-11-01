// Signature packs: large hash lists compiled into a sorted binary file that is
// memory-mapped, so millions of hashes "load" in the time it takes to map a file.
#pragma once

#include "common.hpp"

#include <memory>

namespace veyl {

enum HashKind : int { kMd5 = 0, kSha1 = 1, kSha256 = 2, kHashKinds = 3 };
constexpr size_t kDigestLen[kHashKinds] = {16, 20, 32};
const wchar_t* hash_kind_name(int kind);
// Hex length 32/40/64 -> kind, or -1.
int hash_kind_for_hex_len(size_t len);

// On-disk layout, all little-endian:
//   header (256 bytes, below)
//   per hash kind: [prefix index: 65537 x u32 when kSectionIndexed] entries[count]
//     entry = digest bytes, followed by a u32 name id when kSectionNamed
//   names: u32 offsets[name_count + 1] into the UTF-8 blob that follows
// Name id 0 means "no name of its own": the pack's label is reported instead.
// Entries are sorted by digest. The prefix index maps the first two digest bytes to
// the range of entries starting with them, so a lookup touches a page or two.
constexpr char kPackMagic[8] = {'V', 'E', 'Y', 'L', 'S', 'I', 'G', '1'};
constexpr uint32_t kPackVersion = 1;
constexpr uint32_t kSectionIndexed = 1, kSectionNamed = 2;
constexpr uint32_t kIndexSlots = 65537;
constexpr uint64_t kIndexMinEntries = 4096;  // below this a plain binary search is just as fast

#pragma pack(push, 1)
struct PackSection {
    uint64_t offset;  // of the index if indexed, else of the first entry
    uint64_t count;
    uint32_t width;   // bytes per entry
    uint32_t flags;   // kSection*
};
struct PackHeader {
    char magic[8];
    uint32_t version;
    uint32_t header_size;
    uint64_t created;            // FILETIME (UTC); the newest pack with a given label wins
    uint8_t content_sha256[32];  // of everything after the header (for signed packs later)
    char label[64];              // UTF-8, NUL terminated
    PackSection sections[kHashKinds];
    uint64_t names_offset, names_size;
    uint32_t name_count, reserved;
    uint8_t pad[40];
};
#pragma pack(pop)
static_assert(sizeof(PackHeader) == 256);

class SigPack {
public:
    // Maps and validates a pack. Returns null (and *status) if it's missing or malformed.
    static std::unique_ptr<SigPack> open(const std::wstring& path, int* status = nullptr);
    ~SigPack();
    SigPack(const SigPack&) = delete;
    SigPack& operator=(const SigPack&) = delete;

    // On a match, name receives the entry's own name or else the pack label.
    bool find(int kind, const uint8_t* digest, std::wstring& name) const;

    uint64_t count(int kind) const { return sec_[kind].count; }
    uint64_t total() const { return sec_[0].count + sec_[1].count + sec_[2].count; }
    const std::wstring& label() const { return label_; }
    const std::wstring& path() const { return path_; }
    uint64_t created() const { return hdr().created; }
    const uint8_t* content_id() const { return hdr().content_sha256; }

    // For merging an existing pack into a new one.
    const uint8_t* entry(int kind, uint64_t i) const { return sec_[kind].entries + i * sec_[kind].width; }
    std::string entry_name(int kind, uint64_t i) const;  // empty if the entry has none

private:
    SigPack() = default;
    const PackHeader& hdr() const { return *reinterpret_cast<const PackHeader*>(base_); }
    std::string name_at(uint32_t id) const;

    struct Section {
        const uint32_t* index = nullptr;
        const uint8_t* entries = nullptr;
        uint64_t count = 0;
        uint32_t width = 0;
        bool named = false;
    };
    const uint8_t* base_ = nullptr;
    uint64_t size_ = 0;
    Section sec_[kHashKinds];
    const uint32_t* name_offsets_ = nullptr;
    const char* name_blob_ = nullptr;
    uint32_t name_count_ = 0;
    uint64_t name_blob_size_ = 0;
    std::wstring label_, path_;
};

}  // namespace veyl
