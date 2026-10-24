# Virtual FIDO2 Token — Telegram Passkey & WebAuthn Emulator

[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%7C%20Linux-0078D6?style=flat&logo=windows)](https://github.com/SkrudjReal/virtual-fido-tg-gui)
[![UI](https://img.shields.io/badge/GUI-Material%20Design%203-A8C7FA?style=flat&logo=materialdesign)](https://m3.material.io)
[![Protocol](https://img.shields.io/badge/Protocol-CTAP2%20%7C%20FIDO2%20%7C%20U2F-success)](https://fidoalliance.org)

**Virtual FIDO2 Token** is a high-performance software emulator for FIDO2 / WebAuthn hardware security keys (like YubiKey) running over a virtual kernel USB/IP bus. 

Specifically engineered and tuned for **Telegram Desktop passkeys**, multi-account management, and zero-latency Windows WebAuthn authentication with a modern **Material Design 3 (M3)** desktop GUI.

---

## Key Highlights

### 1. Telegram Desktop Passkey Specialization
- **Direct Self-Attestation (`fmt: "none"`)**: Bypasses Windows WebAuthn error codes `0x8007000d` and `0x80090320` by returning clean attestation statements accepted by Telegram and modern WebAuthn relying parties without requiring proprietary hardware CA roots.
- **`userHandle` Preservation**: Restores reliable Relying Party User Entity routing (`CBOR 0x04`) during assertion responses, allowing Telegram to instantly recognize the user ID and log in seamlessly.
- **Multi-Account Passkey Switcher**: Store multiple Telegram accounts on the same virtual token. When authenticating, an interactive Material 3 dialog displays all matching accounts for the domain, letting you pick which profile to sign into with a single click. Also implements `ctapCommandGetNextAssertion` (0x08) for native account enumeration.

### 2. Material Design 3 (M3) Desktop Application
- Built strictly according to [Google Material Design 3 (M3)](https://m3.material.io) specifications with dark theme tokens (`#111318` surface, `#A8C7FA` primary, elevated container cards, and smooth state layer transitions).
- **Interactive Passkey Approval Modal**: Real-time pop-up notification with synthetic Web Audio chimes whenever a service requests passkey registration or authentication.
- **Passkeys Vault Explorer**: Search, inspect, copy Credential IDs, view signature counters, and delete credentials with M3 confirmation dialogs.
- **Live Packet Monitor**: Real-time streaming of all USB/IP, CTAPHID, and CBOR packet exchanges with filters.
- **Offline & Zero-Dependency**: All web assets, SVG icons, and stylesheets are embedded directly into the Go executable via `embed.FS` — no external CDNs or internet access required.

### 3. Embedded Windows Driver & Setup Wizard
- The standalone binary embeds the complete Windows USB/IP virtual host controller suite (`usbip.exe`, `usbip_test.pfx`, `usbip_vhci_ude.inf`, `usbip_vhci_ude.sys`, `usb.ids`).
- **100% Portable**: Dropping `virtual-fido-gui.exe` onto any fresh Windows machine or virtual machine (VMware, VirtualBox, Hyper-V) automatically unpacks drivers to `%LOCALAPPDATA%\VirtualFIDO\bin\` on first run.
- **4-Step Setup Wizard**:
  1. *Windows Testsigning Check*: 1-click configuration (`bcdedit.exe /set testsigning on`) with WOW64 redirection bypass.
  2. *USB/IP Root Certificate*: 1-click import of the root test certificate into Windows Trusted Root Authorities.
  3. *Kernel VHCI UDE Driver*: 1-click driver installation into Windows Device Manager.
  4. *Loopback Verification*: Instant port diagnostic.

### 4. Low-Level CTAPHID & USB Architecture Fixes
- **Zero-Byte CTAPHID Collision Fix**: Eliminated the fatal 64 zero-byte response bug in USB/IP that caused Windows Hello to fail with `"Try another option / Unknown device state"` whenever user approval took longer than 1 second.
- **High-Speed Polling (`BInterval: 5`)**: Replaced the sluggish 255ms endpoint polling rate with standard 5ms polling, matching hardware YubiKey specifications.
- **Deduplicated Keepalive Queue**: Implemented non-blocking `CTAPHID_KEEPALIVE` (`0xBB`, `UPNEEDED`) every 100ms with automatic FIFO purge when final responses are ready, eliminating WebAuthn timeout drops.

---

## Quick Start (Windows)

### Download & Run
1. Download the latest `virtual-fido-gui.exe` from the [Releases](https://github.com/SkrudjReal/virtual-fido-tg-gui/releases) page.
2. Run `virtual-fido-gui.exe`. Windows requests administrator approval automatically.
3. The application will open in an application window (powered by Edge WebView / app mode).

### Initial Driver Setup (First Run Only)
1. In the GUI, open the **Setup & Drivers** tab.
2. Complete the 4 steps:
   - **Step 1: Testsigning Mode** — Click *Enable Testsigning*. (If enabling for the first time, reboot your PC / VM once).
     > *Note for Virtual Machines:* Disable **Secure Boot** in VM settings (VirtualBox/VMware/Hyper-V) so Windows allows test-signed drivers.
   - **Step 2: USB/IP Certificate** — Click *Install Certificate* to trust the bundled Root CA.
   - **Step 3: VHCI Driver** — Click *Install Driver* to install the virtual USB controller.
   - **Step 4: Port Check** — Click *Verify Port* to confirm readiness.
3. Switch back to the **Dashboard** and click **Start Token**.
4. The virtual security key is now attached as a physical USB device in Windows!

---

## Telegram Passkey Usage

1. Open **Telegram Desktop** -> **Settings** -> **Privacy & Security** -> **Passkeys**.
2. Click **Add Passkey**. Windows Hello will display a security key prompt.
3. The Virtual FIDO GUI will pop up an M3 approval modal with sound notification:
   - Click **Approve Creation**.
4. Your passkey is now securely saved into `vault.json`.
5. To log in on another session or device:
   - Select **Log in with Passkey** in Telegram.
   - If you have multiple Telegram accounts stored on the token, the GUI will present an account chooser card. Select your identity and click **Sign In**.

---

## CLI Usage

The project also includes the `demo.exe` command-line interface:

```powershell
# Start GUI from CLI
.\demo.exe gui

# Start daemon in CLI mode (terminal approval prompt)
.\demo.exe start --vault vault.json --passphrase passphrase

# List all stored passkeys in vault
.\demo.exe list --vault vault.json --passphrase passphrase

# Delete a credential by ID prefix
.\demo.exe delete --identity 0a10cf18 --vault vault.json --passphrase passphrase

# Enable PIN protection
.\demo.exe pin enable
```

---

## Building from Source

### Prerequisites
- [Go 1.19+](https://golang.org/dl/)
- Windows 10 / 11 with Developer Mode or Administrator privileges

### Build Binaries

```powershell
# Clone the repository
git clone https://github.com/SkrudjReal/virtual-fido-tg-gui.git
cd virtual-fido-tg-gui

# Build the standalone Windows GUI (administrator manifest, no console window)
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags "-H windowsgui" -o virtual-fido-gui.exe ./cmd/gui

# Build the CLI demo utility
go build -o demo.exe ./cmd/demo
```

---

## Project Structure

```
├── cmd/
│   ├── gui/                # Standalone GUI launcher (virtual-fido-gui.exe)
│   └── demo/               # CLI utility and USB/IP executor (demo.exe)
├── gui/
│   ├── server.go           # HTTP API, SSE packet streaming & approval router
│   ├── driver_bin/         # Embedded Windows USB/IP drivers & tools
│   └── web/                # Material Design 3 SPA (index.html, style.css, app.js)
├── ctap/                   # CTAP 2.0 / WebAuthn protocol implementation
├── ctap_hid/               # CTAPHID USB framing & keepalive coordinator
├── fido_client/            # Multi-account selector & credential orchestrator
├── identities/             # Identity vault, ES256 key generation & AES encryption
├── usb/                    # USB HID descriptor & packet dispatcher (5ms polling)
├── usbip/                  # USB/IP TCP server protocol implementation
└── webauthn/               # WebAuthn data structures and CBOR encoding
```

---

## Cryptography & Security

- **Attestation**: Self-attestation (`fmt: "none"`) generating standard ECDSA P-256 (`ES256`, COSE algorithm `-7`) key pairs.
- **Vault Encryption**: Credentials stored in `vault.json` encrypted using AES-GCM-256 derived via PBKDF2 with SHA-256 and custom salt.
- **User Presence**: Interactive confirmation required via GUI or terminal for every `MakeCredential` and `GetAssertion` transaction.
- **PIN Protection**: Optional token PIN protection conforming to CTAP2 ClientPIN protocol.

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
