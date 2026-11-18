package gui

import (
	"encoding/json"
	"github.com/bulwarkid/virtual-fido/ctap"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPINSettingsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	s := NewServer(path, "isolated-test-vault")
	post := func(pin string) bool {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/pin", strings.NewReader(`{"action":"set","pin":"`+pin+`"}`))
		w := httptest.NewRecorder()
		s.apiPIN(w, r)
		var response struct{ Success bool }
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Success
	}
	for _, pin := range []string{"123", "123456789", "1e10", "+1234"} {
		if post(pin) {
			t.Fatalf("invalid PIN %q accepted", pin)
		}
	}
	s.client.DisablePIN()
	if !post("001234") {
		t.Fatal("valid PIN rejected")
	}
	s = NewServer(path, "isolated-test-vault")
	w := httptest.NewRecorder()
	s.apiPIN(w, httptest.NewRequest(http.MethodGet, "/api/pin", nil))
	var response struct{ Enabled, Configured bool }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Enabled || !response.Configured {
		t.Fatalf("PIN state lost on restart: %s", w.Body.String())
	}
}

func TestUSBIPBackendAndPorts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramW6432", root)
	t.Setenv("ProgramFiles", root)
	if installedUSBIPDir() != "" {
		t.Fatal("missing backend detected as installed")
	}
	dir := filepath.Join(root, "USBip")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "usbip.exe"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got, modern := usbipBackend(); got != dir || !modern {
		t.Fatalf("installed backend not preferred: %s %v", got, modern)
	}
	s := &Server{sseClients: make(map[chan string]bool)}
	if err := s.attachUSBInternal(); err == nil || s.attached {
		t.Fatal("failed USB/IP command was reported as attached")
	}
	if len(s.diagnostics) == 0 || !strings.Contains(s.diagnostics[0].Message, "Attach failed") {
		t.Fatal("attach failure missing from diagnostics")
	}
	for _, tc := range []struct {
		output        string
		modern, valid bool
	}{
		{"0\r\n", false, true}, {"1\r\n", true, true}, {"30\n", true, true},
		{"0\n", true, false}, {"-1", false, false}, {"256", true, false}, {"error", true, false}, {"", false, false},
	} {
		_, err := attachedPort([]byte(tc.output), tc.modern)
		if (err == nil) != tc.valid {
			t.Errorf("attach response %q modern=%v: %v", tc.output, tc.modern, err)
		}
	}
	output := []byte("Imported USB devices\r\nPort 01: device in use at high-speed\r\nPort 12: device in use\r\n")
	if !hasPort(output, "1") || !hasPort(output, "12") || hasPort(output, "0") || hasPort(output, "2") {
		t.Fatal("port parsing matched the wrong device")
	}
}

func TestInstallerMutationsRequirePOST(t *testing.T) {
	s := &Server{}
	for _, handler := range []http.HandlerFunc{s.apiInstallerDriver, s.apiInstallerUninstall} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/api/installer", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET could mutate driver settings: status %d", w.Code)
		}
	}
}

func TestEmbeddedSignedInstallerIntegrity(t *testing.T) {
	path, err := prepareSignedInstaller(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := verifySignedInstaller(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySignedInstallerHash(path); err == nil {
		t.Fatal("tampered installer passed verification")
	}
}

func TestSignedSetupRequiresStoppedToken(t *testing.T) {
	s := &Server{running: true}
	w := httptest.NewRecorder()
	s.apiInstallerDriver(w, httptest.NewRequest(http.MethodPost, "/api/installer/driver", nil))
	if !strings.Contains(w.Body.String(), "Stop the token") {
		t.Fatal("running token did not prevent setup")
	}
}

func TestMissingSignedDriverDoesNotStartLegacy(t *testing.T) {
	t.Setenv("ProgramFiles", t.TempDir())
	t.Setenv("ProgramW6432", t.TempDir())
	s := &Server{sseClients: make(map[chan string]bool)}
	if err := s.StartDaemon(); err == nil || s.running {
		t.Fatal("token started without signed USBip")
	}
	if dir, _ := usbipBackend(); dir != "" {
		t.Fatal("missing signed driver silently fell back to a legacy binary")
	}
}

func TestLocalUIRejectsForeignOrigins(t *testing.T) {
	host := "127.0.0.1:8080"
	handler := localUIHandler(host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		host, origin string
		status       int
	}{
		{host, "", 204}, {host, "http://" + host, 204}, {host, "https://example.org", 403}, {"example.org:8080", "", 403}, {host, "null", 403},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/api/pin", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("host=%s origin=%s: %d", tc.host, tc.origin, w.Code)
		}
	}
}

func TestAccountSelectionRespectsDenial(t *testing.T) {
	choice := make(chan int, 1)
	s := &Server{pendingSelections: map[string]chan int{"selection": choice}, approvalReqDetails: make(map[string]ApprovalRequestPayload)}
	w := httptest.NewRecorder()
	s.apiApprove(w, httptest.NewRequest(http.MethodPost, "/api/approve", strings.NewReader(`{"id":"selection","approved":false,"selectedIndex":0}`)))
	if got := <-choice; got != -1 {
		t.Fatalf("denied selection chose account %d", got)
	}
}

func TestExpiredApprovalIsRejected(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.apiApprove(w, httptest.NewRequest(http.MethodPost, "/api/approve", strings.NewReader(`{"id":"expired","approved":true}`)))
	if w.Code != http.StatusGone {
		t.Fatalf("expired request reported success: status %d, body %s", w.Code, w.Body.String())
	}
}

func TestVaultSaveNotifiesUIAfterPersistence(t *testing.T) {
	s := NewServer(filepath.Join(t.TempDir(), "vault.json"), "isolated-test-vault")
	events := make(chan string, 8)
	s.sseClients[events] = true
	s.client.SetPIN([]byte("123456"))
	for len(events) > 0 {
		if strings.HasPrefix(<-events, "event: vault_changed\n") {
			reloaded := NewServer(s.vaultFilename, s.vaultPassphrase)
			if reloaded.client.PINHash() == nil {
				t.Fatal("UI was notified before the vault was persisted")
			}
			return
		}
	}
	t.Fatal("saved vault did not notify UI")
}

func TestDiagnosticsExcludeRawProtocolAndVault(t *testing.T) {
	s := NewServer(filepath.Join(t.TempDir(), "private-vault.json"), "private-passphrase")
	s.Write([]byte("[CTAP] RAW payload that must not be exported\n"))
	ctap.NewCTAPServer(s.client).HandleMessage([]byte{0xff})
	w := httptest.NewRecorder()
	s.apiDiagnostics(w, httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil))
	for _, forbidden := range []string{"RAW payload", "private-vault", "private-passphrase"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("diagnostic report disclosed %s", forbidden)
		}
	}
	if !strings.Contains(w.Body.String(), "status=0x01") {
		t.Fatal("CTAP failure missing from report")
	}
}
