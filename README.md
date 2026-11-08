<div align="center">

# ✦ Virtual FIDO2 Token

Software FIDO2 and U2F authenticator for Telegram and other WebAuthn services.

[![Issues](https://img.shields.io/github/issues/SkrudjReal/virtual-fido-tg-gui?style=for-the-badge&color=c4b5fd&labelColor=19152e)](https://github.com/SkrudjReal/virtual-fido-tg-gui/issues)
[![Pull requests](https://img.shields.io/github/issues-pr/SkrudjReal/virtual-fido-tg-gui?style=for-the-badge&color=a5b4fc&labelColor=19152e)](https://github.com/SkrudjReal/virtual-fido-tg-gui/pulls)
[![Stars](https://img.shields.io/github/stars/SkrudjReal/virtual-fido-tg-gui?style=for-the-badge&color=f0abfc&labelColor=19152e)](https://github.com/SkrudjReal/virtual-fido-tg-gui/stargazers)
[![Forks](https://img.shields.io/github/forks/SkrudjReal/virtual-fido-tg-gui?style=for-the-badge&color=c4b5fd&labelColor=19152e)](https://github.com/SkrudjReal/virtual-fido-tg-gui/forks)

[Download Windows GUI](https://github.com/SkrudjReal/virtual-fido-tg-gui/raw/refs/heads/main/virtual-fido-gui.exe) · [Quick start](#-quick-start) · [Build](#-build-from-source) · [Details](COMPATIBILITY_REPORT.md) · [Issues](https://github.com/SkrudjReal/virtual-fido-tg-gui/issues)

</div>

---

Virtual FIDO creates a virtual USB security key with a local GUI, credential vault and approval prompts. The Windows GUI bundles the official signed [USBip 0.9.8.1](https://github.com/vadimgrn/usbip-win2/releases/tag/v.0.9.8.1) installer; the GUI verifies its SHA-256 and Windows Authenticode signature before opening setup.

| Feature | Support |
| :--- | :--- |
| Windows GUI | Windows 10 x64 1903+ and Windows 11 x64; administrator rights required |
| Authenticator | FIDO2, CTAP2 and U2F; multiple accounts and PIN support |
| Driver | Microsoft-signed USBip package; Test Mode is not required |
| Diagnostics | **Event Logs → Save diagnostics** while the app is running |

## ✦ Quick start

1. [Download `virtual-fido-gui.exe`](https://github.com/SkrudjReal/virtual-fido-tg-gui/raw/refs/heads/main/virtual-fido-gui.exe) and run it. Windows requests administrator rights when needed.
2. Open **Setup & Drivers → Install signed USBip**, complete the official installer and restart Windows. Installation can briefly reconnect USB devices.
3. Relaunch the GUI and click **Start Token**. Check that the daemon is running and USB is attached.
4. Set a token PIN under **PIN & Security** for services that require user verification. Test registration and sign-in with a test account before relying on a credential.

If migrating from the old test-signed controller, stop the token and remove that controller using its original uninstaller before disabling Test Mode. The new GUI does not change Windows boot settings or import a test certificate. Restart Windows after changing Test Mode.

The default vault file is `vault.json` in the working directory and the default passphrase is `passphrase`. Back up an existing vault and keep its original passphrase when moving or upgrading the app. The `--vault` and `--passphrase` flags select an existing vault; command-line arguments can be visible to other local processes.

> [!NOTE]
> This is a software authenticator, not certified hardware. A service requiring trusted hardware attestation, a platform authenticator, or an unsupported extension may reject it. Keep another tested sign-in method available.

## ✧ Build from source

Install Go 1.19 or newer. Cross-compile from Linux:

```bash
git clone https://github.com/SkrudjReal/virtual-fido-tg-gui.git
cd virtual-fido-tg-gui
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags '-s -w -H windowsgui' -o virtual-fido-gui.exe ./cmd/gui
```

Or build from Windows PowerShell after cloning:

```powershell
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -trimpath -ldflags "-s -w -H windowsgui" -o virtual-fido-gui.exe ./cmd/gui
```

The build embeds the unmodified signed USBip installer from `gui/signed_driver/`. The GUI executable itself is not Authenticode-signed. The `demo.exe` CLI is retained as a development demo; its Windows USB/IP command uses the legacy source-tree driver layout rather than the GUI's signed-driver setup.

For protocol fixes, validation scope, diagnostics and known limits, see [COMPATIBILITY_REPORT.md](COMPATIBILITY_REPORT.md) and [RELAUNCH_FIX.md](RELAUNCH_FIX.md).

## ◇ Attribution

Based on [BulwarkID/virtual-fido](https://github.com/bulwarkid/virtual-fido) under the [MIT License](LICENSE). The embedded USBip installer is distributed by its [upstream project](https://github.com/vadimgrn/usbip-win2); its provenance and checksum are recorded in [PROVENANCE.txt](gui/signed_driver/PROVENANCE.txt).
