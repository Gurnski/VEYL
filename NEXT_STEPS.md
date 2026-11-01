# Next steps

Picked from TODO.md for the next session. TODO.md has the full list.

## Detection: done so far (1 November)

- MD5 and SHA-1 matching. They're only computed when a loaded list has that kind of hash.
- Signature packs: imported lists compile into a memory-mapped `.vdb` file. A million MD5s compile in 465 ms and load in 3.4 ms.
- Signatures page: "Import hash lists…" (multi-select, VirusShare files go into a "VirusShare" pack), a "Hash packs" list with Remove, and counts by hash kind.
- Native tests cover packs. A throwaway C# program also checked the P/Invoke wrappers end to end. `dist\VEYL-Setup.exe` is rebuilt with all of this.
- Not tested: the Windows 10 path for removing a pack another user's VEYL still has open (it gets renamed to `.removed`). This PC is Windows 11, which just deletes it.

## Detection: still to do

- Try a real import: all the VirusShare `.md5` files in one go. Note how long it takes, the pack size and VEYL's peak memory in Task Manager (expect several hundred MB while it sorts).
- MalwareBazaar and URLhaus downloads, with the Auth-Key entered in Settings. Big feeds should compile into packs in the app, since the launcher only gives feeds 15 s.
- Signed signature packs, so a tampered or planted pack gets rejected. The header already has a SHA-256 of the body and a version field for this.
- Later: YARA rules, scanning inside archives

## Also queued

- **Windows 11 main right-click menu.** "Scan with VEYL" and "Run in VEYL sandbox" with the VEYL logo in the first menu, not just under "Show more options". Needs a small C++ menu handler DLL (`IExplorerCommand`) registered through a signed sparse MSIX package, with setup trusting a self-signed certificate on this PC. The old entries stay for Windows 10 and "Show more options".
- **Sandbox regression tests.** Add cases to `Veyl.Sandbox.Tests` for last night's two bugs: a `requireAdministrator` program, and a folder created with an admin-only permission list. Both were only tested by hand.
- **`.msi` support, moved up.** Many installers are `.msi` underneath (Intel Bluetooth is), and they stop with 1631 in the sandbox today. Needs research: Windows Installer runs as a service outside the sandbox, so the options are reading what the `.msi` would do from its tables without running it, or an admin-mode install inside a throwaway VM-style session.
- **32-bit monitor DLL.** CCSetup runs but VEYL can't see why it exits with 0xC0000409. A 32-bit build of the monitor (`Veyl.SandboxHook32.dll`) would show that, and covers a lot of older installers.
- **Registry redirection** in the sandbox, so installers that write settings keep working.
- **"Files it made" browser** in the sandbox report: open, scan or extract a file the program created.

## Further out

- **Vault:** import from Chrome/Edge/Firefox CSV, Bitwarden JSON and KeePass CSV; password health with a Have I Been Pwned check (only 5 hash characters leave the PC); TOTP 2FA codes; Windows Hello unlock.
- **Kernel driver**, the biggest job on the list. Needs the WDK installed and a Windows VM for testing, because a driver bug blue-screens the PC. This PC runs Windows 11 Home, which doesn't include Hyper-V, so use VirtualBox or VMware.

## Things to bring

- abuse.ch Auth-Key (free, from auth.abuse.ch)
- VirusShare hash lists, or wherever else the keys come from

## Done last night

- Drag-and-drop into elevated VEYL works (the 03:06 drop of `0.744.0.7441080_decrypted.exe` scanned clean). Desktop scan: 437 files in about 4 seconds.
- Dropped files now get a result pop-up, a named result title and a card flash. "1 files" now reads "1 file".
- Sandbox "(IoError)": programs that demand admin were refused by Windows. They now start as the sandboxed user, the way Sandboxie does it, and errors give Windows' own reason.
- Sandbox redirect bug: installers that locked their unpack folder to administrators locked themselves out of the sandbox copy. Fixed.
- The sandbox report explains common exit codes, and it no longer logs "already exists" noise from folder checks.
- Failed sandbox starts clean up their empty run folders.
