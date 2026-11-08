# Virtual FIDO signed-driver MVP

Prepared on 2026-11-06 from `d6c60c5` of SkrudjReal/virtual-fido-tg-gui.

## Windows Test Mode

The bundled `usbip_vhci_ude` driver is test signed. Its certificate and installation do not make it loadable after Test Mode is disabled and Windows is rebooted. Windows checks driver signatures when loading the driver, rather than only during installation. Enabling Test Mode once is therefore insufficient for this driver.

The signed-driver MVP embeds the unmodified official **usbip-win2 0.9.8.1 x64** installer directly in the GUI executable. Setup & Drivers opens its interactive wizard after SHA-256 and Windows Authenticode verification. The wizard uses `/NORESTART`, compact components and the Visual C++ runtime task; it does not automatically reboot Windows. The app does not enable Test Mode or import a test certificate. Its upstream release provides Microsoft-signed drivers. This keeps USB/IP and the existing vault/protocol implementation, and supports Windows 10 x64 1903+ and Windows 11 x64 without writing a new driver or a Windows-only credential provider. The application prefers `Program Files/USBip/usbip.exe`, passes `attach --terse --once`, records the returned port, and detaches that port only. There is no automatic legacy fallback: the token refuses to start until the signed USBip client is installed. Setup is blocked while the token or another setup is running. Existing test-signed drivers must be removed through their original uninstaller before turning off Test Mode.

The downloaded installer SHA-256 matches the GitHub release asset digest:

```text
38cad6d4432b52d5bb9409d9ad03b72fdffc4ada4cd3a48fbeca1a2752a8518a  USBip-0.9.8.1-x64.exe
```

Windows `Get-AuthenticodeSignature` returned `Valid` / `Signature verified` for the unmodified installer, signed by Cloudyne Systems (Scheibling Consulting AB). This verifies the installer signature, not device enumeration or successful loading of its embedded drivers. Local innoextract 1.9 could not inspect the newer installer format; no driver installation was performed on the host.

Sources:

- [Microsoft: loading test-signed code](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) — loading policy and reboot requirement.
- [USBip 0.9.8.1 release](https://github.com/vadimgrn/usbip-win2/releases/tag/v.0.9.8.1) — released package and certification report.
- [USBip README](https://github.com/vadimgrn/usbip-win2) — supported Windows versions, installation effects, and signed drivers.
- [Microsoft: plugin passkey manager support](https://learn.microsoft.com/en-us/windows/apps/develop/security/third-party) — a driverless Windows 11 route exists, but requires a separate provider implementation. It is not implemented in this MVP and does not solve Windows 10 support.

## Confirmed source defects fixed

| Defect | Change |
| --- | --- |
| GUI PIN status always returned false; saving a PIN did not enable its use | Actual enabled/configured status, persisted PIN enablement, matching 4–8 digit GUI/API validation |
| ClientPIN key agreement omitted the P-256 curve | Correct curve and fixed-width coordinates; fixed-width ECDH shared secret and credential public coordinates |
| Signature counter advanced after signing and was never saved on the new multi-account path | Use the existing persistent client assertion path before signing |
| Unsupported `uv` requests could succeed without verification | Reject built-in UV requests; use the implemented ClientPIN protocol for verified requests |
| Exclude lists were ignored | Return credential-excluded after approval instead of creating duplicates |
| Invalid CTAP commands/CBOR could panic | Protocol error responses and boundary validation |
| PIN exhaustion could panic and reboot reset its retry count | Zero retries are supported and persisted; changed PIN invalidates the prior token |
| Account selection rejection could still choose the first account | Propagate denial instead of falling back to an account |
| GUI claimed attachment based on a timer and hard-coded port 0 | Check command exit status, returned port and actual driver port output |
| Portable legacy bundle depended on a missing helper and test-signed driver | The signed GUI no longer embeds or runs the legacy driver/helper/certificate |
| USB requests were selected from an unordered map | Track submission order explicitly and support safe callback reentry |
| Saving could truncate the existing vault on failure | Write, sync and replace a temporary file; report save failures |

The elevated HTTP API also checks Host/Origin and requires POST for setup. Testsigning and test-certificate API routes have been removed. No driver, boot configuration, certificate store or existing user vault was modified during development.

Protocol reference: [FIDO CTAP 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).

## Runtime diagnostics

In the updated application, use **Event Logs → Save diagnostics**, or open `http://127.0.0.1:8080/api/diagnostics`. The endpoint stays available while the app is running and keeps the last 300 diagnostic events in memory. Save the report before closing the app.

The report includes build/platform, selected backend, running/attached state, port, PIN enabled/configured booleans, attach/detach failures and CTAP command/status codes. It excludes the vault filename, vault password, PIN/hash/token, private keys, account records and raw protocol packets. The existing live packet viewer remains separate.

Useful CTAP statuses: `0x00` success, `0x19` credential excluded, `0x26` unsupported algorithm, `0x27` user denied, `0x2C` unsupported option, `0x2E` no credentials, `0x31` incorrect PIN, `0x32` PIN blocked, `0x33` PIN authentication invalid, `0x35` no PIN configured, `0x36` PIN required.

## Verification and limits

Regression tests reproduced counter persistence, invalid key-agreement metadata and CTAP panics before the fixes. Tests cover PIN set/get-token/verified registration and assertion, invalid PIN authentication, persisted PIN block, assertion signature verification, user handles, excluded credentials, malformed requests, GUI/API PIN persistence on disk, backend/port parsing, command failure reporting, account denial, local API access checks, diagnostic redaction, and FIFO/cancellation/reentry.

The full suite runs with `CGO_ENABLED=0` in Linux and as cross-compiled Windows test executables launched natively through PowerShell from isolated Windows temporary directories. The existing macOS CGO package requires CoreFoundation and prevents an ordinary Linux `go test ./...`; it is excluded by CGO-disabled Windows/Linux builds. Windows runs use `-p 1` because concurrent WSL interop launches intermittently fail with `UtilAcceptVsock`. An earlier native test failure exposed the FIFO defect and an invalid original test, both addressed here.

The GUI JavaScript has syntax validation and mock DOM/API checks for signed setup and PIN settings. New tests verify the actual embedded installer hash, successful native Windows Authenticode verification, rejection of tampered bytes, setup refusal while running, and refusal to fall back to a test-signed driver. Go vet and focused race checks are included in the validation evidence distributed with the package.

The final signed GUI executable was also started natively on Windows with an isolated vault path and autostart disabled. Its live diagnostic and installer-status endpoints responded; a Start Token request correctly refused to run without signed USBip and recorded the failure. The test process was stopped afterwards. No installer was launched during this smoke check.

**Not verified:** installation/loading of either USB/IP driver, real USB enumeration, Secure Boot/HVCI behavior, browser/native-app WebAuthn dialogs, or registration/login on Telegram, Google, Microsoft, GitHub or other services. This is a compatibility test build, not a claim of FIDO certification or universal site compatibility. Services requiring trusted hardware attestation, platform-only authenticators, or unsupported extensions may reject it. The unchanged vault defaults are for the prototype; preserve the existing passphrase when opening an existing vault.

## Rebuild

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go vet ./...
node --check gui/web/app.js
node gui/web_test.cjs
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags '-s -w -H windowsgui' -o release/virtual-fido-gui.exe ./cmd/gui
```

Windows test executables can be built with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c ./ctap` and the equivalent command for each test package, then run on Windows. The shipped executable retains the existing administrator manifest and is not Authenticode-signed by this project. Source changes are local; nothing was pushed or published.
