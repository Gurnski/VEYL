# VEYL TODO

Rough order, biggest wins first within each area. Tick things off as they land.

## Kernel driver (real-time blocking)

The goal is to stop a bad file before it runs or gets written, instead of reacting afterwards like the current folder watcher.

- [ ] Install the Windows Driver Kit (WDK) matching VS 2022 and the 10.0.22621 SDK
- [ ] `native/Veyl.Driver`: a file system minifilter (`FltRegisterFilter`) with pre-create and post-cleanup callbacks on executable/script extensions
- [ ] Kernel-to-user channel with `FltCreateCommunicationPort`: the driver asks, the user-mode service answers allow/block, with a timeout that fails open so a hung service can't freeze the PC
- [ ] Process creation callback (`PsSetCreateProcessNotifyRoutineEx`) to block known-bad executables at launch
- [ ] Image load callback (`PsSetLoadImageNotifyRoutine`) to catch bad DLLs
- [ ] Protect VEYL's own files, process and registry keys from tampering (`ObRegisterCallbacks`)
- [ ] Move scanning into a Windows service (`Veyl.Service`, runs as SYSTEM) so protection works before anyone signs in. The tray app becomes a client over a named pipe
- [ ] Development: test signing (`bcdedit /set testsigning on`) in a VM, never on the main PC first. A driver bug is a blue screen
- [ ] Release signing: an EV code-signing certificate plus Microsoft attestation signing through the Partner Center hardware dashboard. Without that, Windows won't load the driver with Secure Boot on
- [ ] Early Launch Anti-Malware (ELAM) driver and Security Center registration. Both need Microsoft's antimalware partner programme (MVI), so this is last

## Sandbox ("Run in VEYL sandbox")

Right-click any `.exe` → "Run in VEYL sandbox". The program runs isolated, VEYL shows a live report of what it tries to do, and nothing reaches the real system.

- [x] Explorer context menu entry for `.exe`, `.bat`, `.cmd` (added by setup). `.ps1`/`.vbs`/`.js` work from the Sandbox page
- [x] Isolation: low-integrity restricted token + job object (no clipboard, no other windows, tree killed on close). This is the hard boundary, enforced by Windows
- [x] File write redirection (Sandboxie-style copy-on-write into `%LOCALAPPDATA%Low\VEYL\Sandbox\<run>\drive`), including deletes and renames, so the program sees its own changes
- [x] Behaviour monitor DLL hooking ntdll: files, registry, child processes (followed and monitored), injection, driver loads, network (blocked)
- [x] Sandbox page: live timeline, filters, plain-English verdict, "Block this file" and "Quarantine it"
- [x] Five-minute time limit, Stop button, firewall rule for the program while it runs (when VEYL is elevated)
- [x] 32-bit monitor DLL (`Veyl.SandboxHook32.dll`), loaded through the import table. Still unmonitored: 32-bit .NET, ARM, and 64-bit children of 32-bit programs
- [ ] Registry redirection into `HKCU\Software\AppDataLow\VEYL\<run>` so installers that write settings keep working (today those writes are blocked and logged)
- [ ] Follow children launched with a custom environment block (they currently run isolated but unmonitored)
- [ ] DNS lookups in the network log (today only connection attempts are seen)
- [ ] "Files it made" browser in the report: open, scan or extract a sandboxed file
- [ ] `.msi` support: needs its own approach, since the Windows Installer service does the real work outside the sandbox
- [ ] Kernel-side enforcement (with the driver): block direct syscalls that skip the hooks; isolation already holds without it, visibility doesn't

## Vault

- [x] Recovery key: shown once when the vault is created, as a printable/saveable code. The vault key gets wrapped twice, by the master password and by the recovery key, so either can open it (vault format v2, with v1 migration)
- [ ] Printable recovery sheet (PDF/print dialog) next to Copy and Save
- [ ] Optional Windows Hello unlock (PIN/fingerprint) on top of the master password
- [ ] Import from browsers and other managers (Chrome/Edge/Firefox CSV, Bitwarden JSON, KeePass CSV)
- [ ] Export to encrypted backup file
- [ ] Password health: reused, weak and old passwords; breached check through Have I Been Pwned's k-anonymity range API (only the first 5 hash characters leave the PC)
- [ ] TOTP (2FA codes) stored per entry
- [ ] Argon2id instead of PBKDF2 for the key derivation (memory-hard)
- [ ] Browser extension for autofill (needs a native messaging host)

## Signatures and detection

- [ ] MalwareBazaar and URLhaus feeds via a free abuse.ch Auth-Key entered in Settings (keys being sourced: abuse.ch, VirusShare and others)
- [x] MD5 and SHA-1 hash support in the engine (most public lists, e.g. VirusShare, are MD5). Only computed when a loaded list needs them
- [x] Hash database as a sorted binary file instead of text: memory-mapped signature packs (`*.vdb`), a million hashes load in about 3 ms
- [ ] Feed updates into packs instead of `hashes.txt` (the launcher gives feeds 15 s, so compile big feeds in the app)
- [ ] YARA rules support (libyara, statically linked) with community rule sets
- [ ] Signed signature packs, so a tampered feed file is rejected
- [ ] Scan inside archives (.zip, .7z) and installers
- [x] Multi-threaded scanning and a scan cache (path + size + timestamps), so unchanged files are skipped; cleared when signatures change
- [ ] Key the cache on NTFS file ID + USN journal instead, so even timestamp-faking malware can't hide behind it (real-time checks already bypass the cache)
- [ ] Scan progress as a percentage (count files first, or estimate from the previous scan)
- [ ] Scheduled scans
- [ ] Optional VirusTotal hash lookup (free API key) for suspicious files

## Installer

- [x] Single `VEYL-Setup.exe` in the VEYL style instead of PowerShell scripts
- [x] Prerequisite checks: Windows version, 64-bit, disk space, admin rights. Runtime ships self-contained
- [x] Post-install self-test: files hashed, task registered, engine and vault crypto run (`Veyl.App.exe --selftest`)
- [x] Repair and upgrade modes that keep vaults and settings
- [x] Install log in `C:\ProgramData\VEYL\logs`
- [ ] Auto-update: download, verify signature, swap files, restart
- [x] Uninstall from Settings > Apps without needing PowerShell
- [ ] Shrink the installer (135 MB): framework-dependent build plus automatic .NET runtime download, or trimming once WPF supports it

## App

- [x] Drag files and folders onto Scan or Sandbox
- [x] Check drag-and-drop by hand while VEYL runs elevated (WM_DROPFILES fallback works)
- [x] Clearer feedback after dropping a file: toast, named result title, card flash
- [x] Vault shortcuts: Ctrl+F search, Ctrl+N add, Ctrl+L lock, Esc clears search, double-click copies a password
- [x] Windows 11 top-level right-click menu entries with the VEYL logo (`IExplorerCommand` handler DLL plus a signed sparse MSIX package). Signed with a local self-signed certificate for now; a real code-signing certificate before any wider release
- [ ] Command palette (Ctrl+K) to jump to any page or action
- [ ] Scan history with per-scan detail pages
- [ ] Allow-list (trusted files and folders)
- [ ] USB drive scan on insert
- [ ] Startup items manager (what runs at boot, with scan verdicts)
- [ ] Network view: which processes are connecting where
