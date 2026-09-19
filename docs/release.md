# Windows build and release notes

Run the installer build from a Windows MSVC development environment:

```powershell
.\scripts\build-installer.ps1
```

The script builds the one-shot elevated helper, names it with the current Rust target triple as required by Tauri sidecar packaging, installs locked frontend dependencies, and builds both current-user NSIS and MSI packages. Use `-Debug -Bundle nsis` for a faster local packaging check.

Windows 11 supplies WebView2 in normal installations. Tauri's default installer behavior still checks for it and uses the bootstrapper when needed. MSI creation depends on WiX and the Windows VBSCRIPT optional feature.

Generated installers are unsigned development artifacts until the owner configures certificate custody and a Tauri `signCommand` or compatible Windows signing flow. Do not publish an unsigned artifact as a Local Pilot release. The updater host, updater public key, publisher identity, release license, and clean-machine upgrade test remain release gates.
