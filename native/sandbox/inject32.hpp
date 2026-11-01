// Loads Veyl.SandboxHook32.dll into a suspended 32-bit process by adding it to the front
// of the program's import table, the way Microsoft Detours does it.
//
// The 64-bit monitor goes in with an APC that calls LoadLibraryW. That doesn't work for a
// 32-bit program: its 32-bit kernel32 isn't loaded yet when the process is created, so
// there's no LoadLibraryW to call. Adding an import instead makes Windows' own 32-bit
// loader load the monitor, after kernel32 and before any of the program's code runs.
//
// Used by the engine (sandbox.cpp, 64-bit) for the first program, and by both monitor
// builds for child processes. Header-only so each binary compiles its own copy.
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstring>
#include <string>
#include <vector>

namespace veyl_inject {

// Machine type of an executable file on disk (IMAGE_FILE_MACHINE_*), or 0 if it isn't a PE.
inline WORD exe_machine(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BYTE head[4096];
    DWORD got = 0;
    ReadFile(h, head, sizeof head, &got, nullptr);
    CloseHandle(h);
    if (got < 0x40 || head[0] != 'M' || head[1] != 'Z') return 0;
    LONG pe;
    memcpy(&pe, head + 0x3C, sizeof pe);
    if (pe <= 0 || (DWORD)pe + 6 > got || memcmp(head + pe, "PE\0\0", 4) != 0) return 0;
    WORD machine;
    memcpy(&machine, head + pe + 4, sizeof machine);
    return machine;
}

inline bool read(HANDLE p, ULONG_PTR at, void* out, SIZE_T n) {
    SIZE_T got = 0;
    return ReadProcessMemory(p, reinterpret_cast<void*>(at), out, n, &got) && got == n;
}

inline bool write(HANDLE p, ULONG_PTR at, const void* in, SIZE_T n) {
    SIZE_T done = 0;
    return WriteProcessMemory(p, reinterpret_cast<void*>(at), in, n, &done) && done == n;
}

// Where the program's .exe is mapped, from the PEB (the kernel fills it in at creation).
inline ULONG_PTR image_base(HANDLE process) {
    using Query = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    PROCESS_BASIC_INFORMATION pbi{};
    if (!query || query(process, ProcessBasicInformation, &pbi, sizeof pbi, nullptr) < 0 || !pbi.PebBaseAddress) return 0;
    // The PEB this returns has our own pointer size (a 32-bit target still has a 64-bit PEB),
    // and ImageBaseAddress is the second pointer in winternl's Reserved3.
    ULONG_PTR base = 0;
    ULONG_PTR at = reinterpret_cast<ULONG_PTR>(pbi.PebBaseAddress) + offsetof(PEB, Reserved3) + sizeof(PVOID);
    return read(process, at, &base, sizeof base) ? base : 0;
}

// Adds `dll` (a full path) as the first import of a suspended 32-bit process.
inline bool add_import32(HANDLE process, const std::wstring& dll) {
    // The import table stores the name as an ANSI string.
    BOOL lossy = FALSE;
    int n = WideCharToMultiByte(CP_ACP, 0, dll.c_str(), -1, nullptr, 0, nullptr, &lossy);
    if (n <= 1 || lossy) return false;
    std::string name(n, '\0');
    WideCharToMultiByte(CP_ACP, 0, dll.c_str(), -1, name.data(), n, nullptr, nullptr);

    ULONG_PTR base = image_base(process);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS32 nt{};
    if (!base || !read(process, base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !read(process, base + dos.e_lfanew, &nt, sizeof nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        return false;
    auto& dirs = nt.OptionalHeader.DataDirectory;
    // .NET programs start through mscoree with their own rules for imports. Leave them alone.
    if (dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress) return false;

    std::vector<IMAGE_IMPORT_DESCRIPTOR> old;
    if (DWORD rva = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        for (int i = 0; i < 4096; ++i) {
            IMAGE_IMPORT_DESCRIPTOR d{};
            if (!read(process, base + rva + i * sizeof d, &d, sizeof d)) return false;
            if (!d.Name && !d.FirstThunk) break;
            old.push_back(d);
        }
    }

    // New block: descriptors (ours, the originals, terminator), lookup and address tables
    // (one import plus a terminator each), the import-by-name entry, then the DLL name.
    const char kExport[] = "VeylHook";
    size_t descs = (old.size() + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    size_t ilt = descs, iat = ilt + 8, byname = iat + 8, dllname = (byname + 2 + sizeof kExport + 3) & ~size_t(3);
    size_t total = dllname + name.size() + 1;

    // RVAs are 32-bit and relative to the image, so the block has to sit above the image.
    ULONG_PTR at = (base + nt.OptionalHeader.SizeOfImage + 0xFFFF) & ~ULONG_PTR(0xFFFF);
    void* block = nullptr;
    for (; at < 0x7FFF0000 && !block; at += 0x10000)
        block = VirtualAllocEx(process, reinterpret_cast<void*>(at), total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!block) return false;
    ULONG_PTR start = reinterpret_cast<ULONG_PTR>(block);
    auto rva = [&](size_t off) { return (DWORD)(start + off - base); };

    std::vector<BYTE> buf(total, 0);
    IMAGE_IMPORT_DESCRIPTOR ours{};
    ours.OriginalFirstThunk = rva(ilt);
    ours.Name = rva(dllname);
    ours.FirstThunk = rva(iat);
    memcpy(buf.data(), &ours, sizeof ours);
    if (!old.empty()) memcpy(buf.data() + sizeof ours, old.data(), old.size() * sizeof ours);
    DWORD thunk = rva(byname);
    memcpy(buf.data() + ilt, &thunk, 4);
    memcpy(buf.data() + iat, &thunk, 4);
    memcpy(buf.data() + byname + 2, kExport, sizeof kExport);  // hint 0, then the name
    memcpy(buf.data() + dllname, name.c_str(), name.size() + 1);
    if (!write(process, start, buf.data(), buf.size())) return false;

    // Point the header at the new table. Bound imports describe the old table, so drop them.
    IMAGE_DATA_DIRECTORY imp{rva(0), (DWORD)descs}, none{0, 0};
    ULONG_PTR dir_at = base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory);
    DWORD prot = 0;
    SIZE_T span = sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(dir_at), span, PAGE_READWRITE, &prot)) return false;
    bool ok = write(process, dir_at + IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof imp, &imp, sizeof imp) &&
              write(process, dir_at + IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT * sizeof none, &none, sizeof none);
    VirtualProtectEx(process, reinterpret_cast<void*>(dir_at), span, prot, &prot);
    return ok;
}

}  // namespace veyl_inject
