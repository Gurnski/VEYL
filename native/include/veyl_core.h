// VEYL core engine - flat C ABI consumed by the C# front end via P/Invoke.
// All strings crossing the boundary are UTF-16 (wchar_t). Every function returns
// a VEYL_* status code unless noted otherwise.
#pragma once

#include <stdint.h>
#include <wchar.h>

#ifdef VEYL_CORE_EXPORTS
#define VEYL_API extern "C" __declspec(dllexport)
#else
#define VEYL_API extern "C" __declspec(dllimport)
#endif

#define VEYL_CORE_VERSION "0.2.5"

enum VeylStatus {
    VEYL_OK = 0,
    VEYL_ERR_ARG = 1,
    VEYL_ERR_IO = 2,
    VEYL_ERR_AUTH = 3,       // wrong master password or tampered vault
    VEYL_ERR_FORMAT = 4,     // not a vault file / unsupported version
    VEYL_ERR_CRYPTO = 5,
    VEYL_ERR_BUFFER = 6,     // caller buffer too small; required size written back
    VEYL_ERR_NOT_FOUND = 7,
    VEYL_ERR_EXISTS = 8,
    VEYL_ERR_STATE = 9,      // e.g. scanner not initialised
};

// ---------------------------------------------------------------- general
VEYL_API const char* veyl_core_version(void);
VEYL_API int veyl_sha256_file(const wchar_t* path, char out_hex[65]);
// Fills buf with a random password of `length` chars. flags = VEYL_GEN_*.
// buf must hold length + 1 wchar_t.
#define VEYL_GEN_LOWER   0x01
#define VEYL_GEN_UPPER   0x02
#define VEYL_GEN_DIGITS  0x04
#define VEYL_GEN_SYMBOLS 0x08
#define VEYL_GEN_NO_AMBIGUOUS 0x10
VEYL_API int veyl_generate_password(wchar_t* buf, int length, int flags);
VEYL_API void veyl_secure_zero(void* p, int bytes);
// Puts text on the clipboard hidden from clipboard history and clears it after
// clear_after_sec seconds (0 = never) if nothing else was copied meanwhile.
VEYL_API int veyl_clipboard_set_secret(const wchar_t* text, int len, int clear_after_sec);

// ---------------------------------------------------------------- vault
typedef struct VeylVault VeylVault;

// Password arguments are raw UTF-16 buffers with explicit length (no terminator
// required) so callers can pass pinned SecureString memory without making a
// managed string.
VEYL_API int veyl_vault_create(const wchar_t* path, const wchar_t* pw, int pw_len, VeylVault** out);
VEYL_API int veyl_vault_open(const wchar_t* path, const wchar_t* pw, int pw_len, VeylVault** out);
// Opens a vault with its recovery key (dashes, spaces and case don't matter).
// VEYL_ERR_AUTH = wrong key, VEYL_ERR_STATE = this vault has no recovery key.
VEYL_API int veyl_vault_open_recovery(const wchar_t* path, const wchar_t* key, int key_len, VeylVault** out);
// Creates (or replaces) the recovery key and saves. out_key receives it as
// XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX. Any older recovery key stops working.
VEYL_API int veyl_vault_set_recovery(VeylVault* v, wchar_t out_key[40]);
VEYL_API int veyl_vault_has_recovery(VeylVault* v);
VEYL_API int veyl_vault_save(VeylVault* v);
VEYL_API int veyl_vault_change_password(VeylVault* v, const wchar_t* new_pw, int new_pw_len);
VEYL_API void veyl_vault_close(VeylVault* v);

VEYL_API int veyl_vault_count(VeylVault* v);

// Entry fields. Password is deliberately not readable through veyl_vault_get_field;
// use veyl_vault_copy_password or veyl_vault_reveal_password.
enum VeylField {
    VEYL_FIELD_ID = 0,
    VEYL_FIELD_TITLE = 1,
    VEYL_FIELD_USERNAME = 2,
    VEYL_FIELD_URL = 3,
    VEYL_FIELD_NOTES = 4,
    VEYL_FIELD_PASSWORD = 5,
};

// Reads a non-secret field of the entry at `index`. On VEYL_ERR_BUFFER, *len
// receives the required size in wchar_t including terminator.
VEYL_API int veyl_vault_get_field(VeylVault* v, int index, int field, wchar_t* buf, int* len);
VEYL_API int veyl_vault_get_times(VeylVault* v, int index, int64_t* created, int64_t* modified);

// Adds an entry; out_id (37 wchar_t) receives the new entry id.
VEYL_API int veyl_vault_add(VeylVault* v, const wchar_t* title, const wchar_t* username,
                            const wchar_t* pw, int pw_len, const wchar_t* url,
                            const wchar_t* notes, wchar_t out_id[37]);
// Updates an entry. Pass pw = NULL to keep the existing password.
VEYL_API int veyl_vault_update(VeylVault* v, const wchar_t* id, const wchar_t* title,
                               const wchar_t* username, const wchar_t* pw, int pw_len,
                               const wchar_t* url, const wchar_t* notes);
VEYL_API int veyl_vault_delete(VeylVault* v, const wchar_t* id);

// Copies the password to the clipboard (hidden from clipboard history) and
// clears it after `clear_after_sec` seconds if it is still on the clipboard.
VEYL_API int veyl_vault_copy_password(VeylVault* v, const wchar_t* id, int clear_after_sec);
// Writes the password into a caller buffer. Caller must zero it after use.
VEYL_API int veyl_vault_reveal_password(VeylVault* v, const wchar_t* id, wchar_t* buf, int* len);

// ---------------------------------------------------------------- scanner
enum VeylVerdict {
    VEYL_CLEAN = 0,
    VEYL_SUSPICIOUS = 1,
    VEYL_MALICIOUS = 2,
    VEYL_SKIPPED = 3,   // unreadable / locked / too large
};

typedef struct VeylScanResult {
    int verdict;
    int score;              // heuristic score 0-100
    char sha256[65];
    wchar_t threat[128];    // detection name, empty if clean
    wchar_t detail[256];    // human readable reasons
} VeylScanResult;

// Return non-zero to continue, zero to cancel the scan.
typedef int(__stdcall* VeylScanCallback)(const wchar_t* path, const VeylScanResult* result, void* ctx);

// Loads hash signatures: the text file (one "hash[ name]" per line, # comments,
// MD5, SHA-1 or SHA-256 told apart by length) plus every signature pack (*.vdb) in
// the same folder. Call again to reload after a pack is compiled or removed.
VEYL_API int veyl_scanner_init(const wchar_t* signature_file, int use_amsi);
// Total across all hash kinds, capped at INT_MAX.
VEYL_API int veyl_scanner_signature_count(void);
VEYL_API int veyl_scanner_signature_counts(int64_t* md5, int64_t* sha1, int64_t* sha256);
// hash_hex: 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters. Not saved to disk.
VEYL_API int veyl_scanner_add_signature(const wchar_t* hash_hex, const wchar_t* name);

// ---------------------------------------------------------------- signature packs
// A pack is a sorted, memory-mapped hash database, so millions of hashes load
// instantly. Each label (e.g. "VirusShare") has one live pack; compiling a label
// again writes a new file, and the scanner drops the older one on its next init.
//
// Compiles text hash lists (VirusShare .md5 files, "hash name" lines, "hash,name"
// CSV) and/or existing packs (to merge into) into a new pack in out_dir.
// out_path (260 wchar_t, may be NULL) receives its path, *out_hashes the number of
// distinct hashes. VEYL_ERR_FORMAT = no hashes found in the inputs.
VEYL_API int veyl_signature_compile(const wchar_t* const* inputs, int input_count, const wchar_t* label,
                                    const wchar_t* out_dir, wchar_t out_path[260], int64_t* out_hashes);
// Reads a pack's header without loading it. VEYL_ERR_FORMAT = damaged or not a pack.
VEYL_API int veyl_signature_pack_info(const wchar_t* path, wchar_t label[64], int64_t* md5, int64_t* sha1,
                                      int64_t* sha256);
// Packs the scanner has loaded, index from 0. VEYL_ERR_NOT_FOUND past the end.
VEYL_API int veyl_scanner_pack_info(int index, wchar_t label[64], wchar_t path[260], int64_t* hashes,
                                    int64_t* created_unix);
// Unloads a pack and deletes its file.
VEYL_API int veyl_scanner_remove_pack(const wchar_t* path);
VEYL_API void veyl_scanner_shutdown(void);
VEYL_API int veyl_scan_file(const wchar_t* path, VeylScanResult* out);
// Recursively scans a directory on a pool of worker threads, invoking cb (never
// concurrently) for every file examined. out_files / out_threats may be NULL.
VEYL_API int veyl_scan_directory(const wchar_t* path, VeylScanCallback cb, void* ctx,
                                 int* out_files, int* out_threats);

// Scan flags for the _ex variants.
#define VEYL_SCAN_NO_CACHE 0x01  // rescan even if the file is unchanged since a clean scan
VEYL_API int veyl_scan_file_ex(const wchar_t* path, int flags, VeylScanResult* out);
VEYL_API int veyl_scan_directory_ex(const wchar_t* path, int flags, VeylScanCallback cb, void* ctx,
                                    int* out_files, int* out_threats);

// Clean-file cache: files unchanged (path, size, timestamps) since they last scanned
// clean are skipped. Cleared automatically when signatures or AMSI change.
VEYL_API int veyl_scan_cache_load(const wchar_t* path);
VEYL_API int veyl_scan_cache_save(const wchar_t* path);
VEYL_API void veyl_scan_cache_clear(void);
VEYL_API int veyl_scan_cache_count(void);

// ---------------------------------------------------------------- sandbox
typedef struct VeylSandbox VeylSandbox;

#define VEYL_SANDBOX_ALLOW_NETWORK 0x01

// Runs exe isolated (low integrity, restricted token, job object). Activity is logged
// to <root>\events.jsonl and file writes land in <root>\drive\... when hook_dll is
// given and exe is 64-bit (*out_monitored = 1). Closing the sandbox kills the program.
VEYL_API int veyl_sandbox_start(const wchar_t* exe, const wchar_t* args, const wchar_t* root, const wchar_t* hook_dll,
                                int flags, VeylSandbox** out, int* out_pid, int* out_monitored);
VEYL_API int veyl_sandbox_status(VeylSandbox* sb, int* active_processes, int* total_processes, int* exit_code);
VEYL_API int veyl_sandbox_kill(VeylSandbox* sb);
VEYL_API void veyl_sandbox_close(VeylSandbox* sb);

// ---------------------------------------------------------------- quarantine
// Moves a file into the quarantine directory in a defanged (non-executable,
// obfuscated) form. out_id (37 wchar_t) receives the quarantine id.
VEYL_API int veyl_quarantine_file(const wchar_t* path, const wchar_t* quarantine_dir,
                                  const wchar_t* threat, wchar_t out_id[37]);
// Reads the metadata of a quarantined item. original_path must hold 1024 wchar_t,
// threat 128 wchar_t.
VEYL_API int veyl_quarantine_info(const wchar_t* quarantine_dir, const wchar_t* id,
                                  wchar_t* original_path, wchar_t* threat,
                                  int64_t* quarantined_at, int64_t* size);
// Restores to the original location (or to restore_to if not NULL).
VEYL_API int veyl_quarantine_restore(const wchar_t* quarantine_dir, const wchar_t* id,
                                     const wchar_t* restore_to);
VEYL_API int veyl_quarantine_delete(const wchar_t* quarantine_dir, const wchar_t* id);
