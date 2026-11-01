# VEYL

An antivirus and password manager for my own PCs. A launcher checks the install and starts the app, and the app lives in the system tray from sign-in onwards. The C++ engine does the crypto, scanning and quarantine; the C# side (WPF, .NET 8) is the UI.

VEYL runs alongside Windows Defender, not instead of it. It has no kernel driver and no cloud lookups, so treat it as an extra layer.

## Layout

```
native/            Veyl.Core.dll (C++20, MSVC) and its tests
  include/veyl_core.h   the C ABI the C# side calls
  src/crypto.cpp        CNG wrappers: SHA-256, PBKDF2, AES-256-GCM, RNG
  src/vault.cpp         encrypted vault file format
  src/scanner.cpp       hash blocklist, AMSI, heuristics, worker pool, scan cache
  src/signatures.cpp    signature packs: format checks, lookup, the list compiler
  src/quarantine.cpp    defang/restore files
  src/clipboard.cpp     copy secrets without Win+V history, auto-clear
  src/sandbox.cpp       starts programs isolated (restricted token + job object)
  sandbox/hook.cpp      Veyl.SandboxHook.dll: redirects writes, records activity
                        (built twice: Veyl.SandboxHook32.dll is the 32-bit copy)
  sandbox/inject32.hpp  loads the 32-bit monitor through a program's import table
  shellmenu/menu.cpp    Veyl.ShellMenu.dll: Windows 11 main right-click menu
packaging/menu/         sparse package manifest for the Windows 11 menu (Veyl.Menu.msix)
  tests/                core tests, sandbox tests, the "malware-like" probe, v1 vault fixture
src/Veyl.Shared/   P/Invoke wrappers, paths, settings, manifest, theme
src/Veyl.Launcher/ VEYL.exe: splash, integrity/update checks, starts the app
src/Veyl.App/      Veyl.App.exe: the main window and tray icon
src/Veyl.Setup/    VEYL-Setup.exe: installs, updates, repairs and removes VEYL
signatures/        seed hash list (just the EICAR test file)
TODO.md            what's next (kernel driver, sandbox follow-ups, signatures, ...)
tools/make-icon.ps1  regenerates assets/veyl.ico
```

## Building

Needs Visual Studio 2022 with the C++ workload and the .NET 8 SDK.

```powershell
.\build.ps1          # native build + tests, then dist\VEYL-Setup.exe
.\build.ps1 -Sign    # also sign the programs themselves with the same certificate
```

The first build creates a self-signed certificate, "CN=VEYL Local Code Signing", in your personal certificate store. Its private key stays on that PC. Every build signs the Windows 11 menu package (`Veyl.Menu.msix`) with it, because Windows won't register an unsigned package. Back the certificate up with its private key (`certmgr.msc` > Personal > Certificates > Export): a build signed with a different certificate can't update the menu package on PCs that already have it.

The build is self-contained: the .NET runtime ships inside VEYL, so target PCs need nothing installed first. The cost is size. `VEYL-Setup.exe` is about 135 MB and the install about 160 MB.

For day-to-day work, `dotnet build VEYL.sln` puts everything in `out\Release`. Build the native project once first (`build.ps1` does it), since the C# projects copy `native\build\Release\Veyl.Core.dll`. A build without `manifest.json` shows as "Development build" and skips the integrity check.

## Installing

Copy `dist\VEYL-Setup.exe` to the PC and run it. It uses the launcher's look and asks for admin rights once. It then:

1. Checks the PC: Windows 10 1809 or newer, 64-bit, admin rights, enough disk space.
2. Closes any running VEYL, for every user.
3. Unpacks into `C:\Program Files\VEYL.new` and swaps it in, so a failed copy leaves the old install working.
4. Creates `C:\ProgramData\VEYL` and lets every user write to the shared signatures and quarantine folders.
5. Registers the `\VEYL\Launcher` sign-in task (optional).
6. Adds the Start menu shortcut, "Scan with VEYL" and "Run in VEYL sandbox" in Explorer's right-click menu (optional), and a desktop shortcut (optional). On Windows 11 the entries also go in the main menu, not just under "Show more options". That takes a package registration: setup adds VEYL's certificate to the machine's TrustedPeople store (the store Windows checks for app packages, nothing else) and registers `Veyl.Menu.msix` for the user who installs. Other users get it the first time they run VEYL. Uninstall removes the package for every user and the certificate.
7. Registers in Settings > Apps, where Modify and Uninstall open the setup again.
8. Verifies the install: hashes every file against `manifest.json` and runs `Veyl.App.exe --selftest`, which loads the engine, scans a file and round-trips a throwaway vault.

Every run writes a log to `C:\ProgramData\VEYL\logs`. Run it again on an installed PC and it offers Update, Repair or Uninstall. Uninstall keeps vaults and settings unless you tick the box to delete them.

For scripted installs:

```
VEYL-Setup.exe --silent [--no-startup] [--no-menu] [--desktop] [--trust-cert]
VEYL-Setup.exe --uninstall [--silent] [--remove-data]
```

The exit code is 0 on success. `--trust-cert` trusts the certificate from a `build.ps1 -Sign` build.

The sign-in task uses "run with highest privileges", so admin accounts get an elevated VEYL with no UAC prompt and can scan system folders. Standard accounts run it with normal rights.

## How it works

### Startup

`VEYL.exe --autostart` runs at sign-in with no window. It hashes `Veyl.App.exe`, `Veyl.App.dll`, `Veyl.Shared.dll` and `Veyl.Core.dll` against `manifest.json` and refuses to start the app if any of them changed. It then makes sure the user's data folder exists, checks `updateUrl` if one is set, refreshes signature feeds if they're more than 12 hours old, and starts `Veyl.App.exe --tray`. Launched by hand, it does the same behind the splash screen. If the app is already running, the launcher just brings its window forward.

### Users and storage

```
C:\ProgramData\VEYL\
  signatures\hashes.txt       shared blocklist
  quarantine\<id>.vq          shared quarantine
  users\<SID>\vault.veyl      that user's vault (+ vault.veyl.bak)
  users\<SID>\settings.json
  users\<SID>\activity.jsonl
```

Each user folder's ACL allows only that user, SYSTEM and Administrators. Every Windows account gets its own vault and master password.

### Vault

Entries are encrypted with AES-256-GCM under a random 256-bit vault key. That key is stored twice in the file's header, each copy wrapped with AES-256-GCM: once under a key derived from the master password (PBKDF2-HMAC-SHA256, 600,000 rounds) and once under a key derived from the recovery key. Either secret opens the vault, and changing the master password only re-wraps its own copy, so the recovery key keeps working. The whole 184-byte header is authenticated, so tampering with any of it (iteration counts, salts, wrapped keys) makes the open fail. A fresh nonce is used on every save. Saves go to a temp file that then replaces the old one, which is kept as `.bak`. All of this goes through Windows CNG (`bcrypt.dll`); there are no third-party crypto libraries.

The recovery key is 32 characters (160 random bits) in Crockford base32, shown once as eight groups of four when the vault is created. Typing it back ignores case, spaces and dashes, and treats O as 0 and I or L as 1. "Forgot your master password?" on the lock screen takes the key and a new master password. You can make a new key in Vault Settings, which stops the old one working. Lose both the master password and the recovery key and the vault is gone; nobody else can open it.

Vaults made by 0.1.0 (format v1, no recovery slot) are upgraded the first time they're unlocked, and the v1 file is kept as `.bak`. VEYL then shows a banner offering to make a recovery key.

Passwords stay in native memory. The UI reads them only when you click copy (straight from C++ to the clipboard, marked to stay out of Win+V history and cloud clipboard, and cleared after 20 seconds by default) or the eye icon. The vault locks after 5 idle minutes, when Windows locks, and when the PC sleeps. Ctrl+F searches, Ctrl+N adds, Ctrl+L locks, and double-clicking an entry copies its password.

### Scanning

For each file the engine:

1. Hashes it and checks the blocklist (malicious on a match). SHA-256 is always computed. MD5 and SHA-1 are added only when a loaded list contains hashes of that kind, because each one costs time on every file: a fresh scan of `Program Files\dotnet` (5,668 files, warm cache, AMSI off) takes 0.35 s with SHA-256 alone, 0.50 s with MD5 too, and 0.67 s with all three.
2. Asks Defender through AMSI for files under 16 MB (malicious if Defender says so; does nothing if Defender is off).
3. Scores PE files on packer section names, high-entropy code, writable+executable sections, odd entry points, process-injection imports (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` and friends), keyboard hooks and disguised extensions like `invoice.pdf.exe`. Scripts are scored on things like `-EncodedCommand`, `DownloadString`, `vssadmin delete shadows` and Defender exclusions. A score of 50 or more is "suspicious". A valid Authenticode signature takes 40 points off.

Only files that start with `MZ` or have a script extension get read in full, once, and that one buffer is both hashed and scored. Other files are hash-only, and large media files that aren't executables (video, audio, images) skip hashing as well. Run against `Program Files (x86)`, `System32\drivers`, `Program Files\dotnet` and my Downloads folder (135,014 files), it flagged nothing. That says the heuristics are quiet on normal software, not that they catch much.

Directory scans use one thread to walk folders and up to eight workers to scan. Files that scanned clean are remembered by path, size and timestamps (in `users\<SID>\scan.cache`), so a repeat scan skips anything unchanged. Adding signatures or switching AMSI clears that memory, and real-time checks never use it. Tick "Deep scan" to recheck everything anyway. On this PC, `Program Files (x86)` went from 307 s single-threaded to 157 s on the first parallel pass and 10 s on a repeat, and `Program Files\dotnet` from 19 s to 3 s. You can also drop files or folders onto the Scan page (a pop-up gives the result, since one file scans in a fraction of a second), or right-click them in Explorer and choose "Scan with VEYL".

Quick scan covers running programs, Downloads, Desktop, both Startup folders and Temp. Full scan covers every fixed drive. Real-time protection watches Downloads, Desktop, Startup and Temp (editable), waits 1.5 s for a new executable or script to stop changing, scans it, and quarantines known-bad files automatically.

Quarantined files are XORed with a random keystream and stored with their original path, so they can't run and other scanners don't trip over them. You can restore or delete them from the Quarantine page.

### Sandbox

Right-click a program or script in Explorer and choose "Run in VEYL sandbox", drop it on Shield → Sandbox, or pick it with "Run a program…". Scripts (`.ps1`, `.vbs`, `.js`) run through their usual host.

Two layers keep it contained:

1. **Isolation, enforced by Windows.** The program runs with a restricted copy of your token: Administrators is deny-only, privileges are stripped, and the integrity level is Low. Low-integrity processes can't write to your files, to the registry outside `AppDataLow`, or to any normal process, whatever they try. It also runs in a job object that caps it at 64 processes and 4 GB, blocks the clipboard (so it can't read a password you just copied), other windows, display settings and shutdown, and kills the whole tree when the run ends or VEYL closes. After five minutes the run stops itself.
2. **The monitor, `Veyl.SandboxHook.dll`.** VEYL queues it into the program's first thread before that thread runs, and the monitor follows every child process the same way. 32-bit programs get `Veyl.SandboxHook32.dll` instead. Their 32-bit `kernel32` isn't loaded yet when the process is created, so the queued-call trick doesn't work for them. VEYL adds the monitor to the front of the program's import table instead, the way Microsoft Detours does, and Windows' own loader loads it before any of the program's code runs. Children are followed across both kinds, except that a 32-bit program can't reach into a 64-bit child. It patches a few `ntdll` system-call stubs so that file writes, creates, deletes and renames happen on copies under `%LOCALAPPDATA%Low\VEYL\Sandbox\<run>\drive\` (the program sees its own changes; your files don't change). It also records registry writes, programs started, writes or threads into other processes, driver loads (blocked) and network connections (blocked unless you tick "Allow internet"). When VEYL is elevated it also adds a firewall rule for the program while it runs.

The Sandbox page shows the timeline live and turns it into a verdict: persistence (Run keys, Startup folder, services), code injection, drivers, commands that delete backups or disable Defender, mass file changes, dropped executables and network attempts each add to a score. "Block this file" adds its hash to the signatures, and "Quarantine it" moves it to quarantine. The bin icon deletes the run and everything it wrote.

What it can't do yet: 32-bit .NET programs, ARM programs and 64-bit children of 32-bit programs are isolated but not monitored, registry writes are blocked rather than redirected, so some installers won't work, and `.msi` files aren't supported because the Windows Installer service does the real work outside the sandbox. Installers that bundle an `.msi` unpack and start, then stop with exit code 1631. Programs that demand admin rights start anyway as the sandboxed user, so one that checks for admin may quit early. A program that makes system calls directly can dodge the monitor, but not the isolation. See TODO.md.

### Signatures

VEYL matches MD5, SHA-1 and SHA-256 hashes, told apart by length (32, 40 or 64 hex characters). They come from two places in `C:\ProgramData\VEYL\signatures`:

- `hashes.txt` holds one hash per line, optionally followed by a name. Hashes added by hand, "Block a file", the sandbox's "Block this file" and feed updates go here. It's read in full at startup, so it's meant for thousands of hashes, not millions.
- Signature packs (`*.vdb`) hold imported lists. "Import hash lists…" on the Signatures page takes any number of files at once (all 500-odd VirusShare `.md5` files, say), and the engine compiles them into one sorted binary file. Packs are memory-mapped rather than read, so a pack with a million hashes loads in about 3 ms and costs nothing until a lookup touches it. Compiling a million MD5s takes about half a second.

Each pack has a label. Files named `VirusShare_*` go into the "VirusShare" pack and anything else into "Imported". Importing more files under the same label merges them with what's there. A match on a hash with no name of its own reports the label as the threat name ("VirusShare"), and the detail says which hash kind and list matched.

Packs are never edited in place. A rebuild writes a new file named after its label and creation time, the scanner loads the newest pack for each label, and older ones are deleted the next time signatures load, or renamed to `.removed` if another user's VEYL still has them open. The signatures folder is writable by every user, so the loader checks every offset and count in a pack against the file size and ignores a pack that doesn't add up. That stops a damaged pack from crashing the scanner. It doesn't stop someone writing a valid pack of their own; signed packs (see TODO.md) are meant to fix that.

The pack format: a 256-byte header (magic `VEYLSIG1`, version, creation time, SHA-256 of the body, label), then one section per hash kind with sorted fixed-width entries, then an optional name table. Sections with 4,096 entries or more start with a 65,537-entry index on the first two bytes of the hash, so a lookup reads one index slot and binary-searches a small range.

Feeds are any text file of hashes at a URL or path. The free public feeds I tried (MalwareBazaar's export) now require an API key, so none are configured by default.

### Updates

GitHub Releases on [Gurnski/VEYL](https://github.com/Gurnski/VEYL) is the update server. Every build points at `https://github.com/Gurnski/VEYL/releases/latest/download/manifest.json` unless you pass `-UpdateUrl` (`-UpdateUrl ""` turns update checks off). The launcher fetches that file at start-up, and the app fetches it again every 6 hours while it runs (About > "Check for updates" checks straight away). If its version is newer, there's one tray notification and the app's Overview page shows a banner with "Download and install". That downloads `VEYL-Setup.exe` to `%TEMP%\VEYL-Update`, checks its SHA-256 against the release manifest, deletes it if it doesn't match, and starts it. The setup closes VEYL and updates in place.

To publish a release, bump `<Version>` in `src\Directory.Build.props`, commit and push, then run:

```powershell
.\release.ps1            # build, then create release v<version> with VEYL-Setup.exe and manifest.json
.\release.ps1 -Sign      # sign the build first
.\release.ps1 -Replace   # re-upload the files to an existing release of the same version
```

It needs the GitHub CLI signed in (`gh auth login`) and refuses to run with uncommitted or unpushed changes, so the tag matches what was built. The uploaded `manifest.json` is the build's own manifest plus `setupSha256` and `setupSize`. The copy inside the installer can't carry them, since the installer is built after it. Releases aren't marked as drafts or pre-releases, because `releases/latest/download/` skips both.

The repository has to be public for this to work: GitHub doesn't serve release files from a private repository without a sign-in.

## Testing

`build.ps1` runs two native test programs and stops if either fails:

- `Veyl.Core.Tests.exe` covers the vault (round trip, wrong password, a flipped ciphertext byte, header tampering, password change), recovery keys (open, reset, regenerate, wrong and malformed keys), migrating `tests\fixtures\v1.veyl` (written by the 0.1.0 engine), the generator, hashing, the scanner, the scan cache, the worker pool (300 files, serialised callback, cancel), signature packs and quarantine. The pack tests compile VirusShare-style and named lists, match on each hash kind, merge, supersede and remove packs, reject truncated and tampered packs, and time a million-hash pack.
- `Veyl.Sandbox.Tests.exe` runs `Veyl.SandboxProbe.exe` in the sandbox. The probe creates, changes and deletes files in Documents, tries to add itself to the Run key, starts `cmd.exe`, connects to 1.1.1.1:443 and reads the clipboard. The test checks that the probe saw what it expected from inside, that nothing changed on the real system, and that every action was logged.

To check detection end to end, download the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) (its hash is in the seed list). Defender will probably grab it first, so a simpler check is to block any harmless file's hash on the Signatures page, rename a copy to `.exe` and drop it into Downloads.

## Known limits

- No kernel minifilter, so real-time protection reacts just after a file is written instead of blocking the write.
- Windows Security Center doesn't know VEYL exists. That registration needs Microsoft's partner programme.
- The scan cache trusts timestamps, so malware that fakes its file times could be skipped by a repeat scan (not by real-time protection, which always rescans). Deep scan avoids it.
- Watched folders are only the signed-in user's. Nothing scans while nobody is signed in.

## License

VEYL is source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). You can read, run, change and share it for research, study, personal use and noncommercial organisations. Commercial use, including selling it or anything built from it, needs my permission.
