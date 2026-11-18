package gui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"
)

//go:embed web/*
var webFiles embed.FS

type LogEntry struct {
	Time    string `json:"time"`
	Tag     string `json:"tag"`
	Message string `json:"message"`
}

type ApprovalRequestPayload struct {
	ID              string           `json:"id"`
	Type            string           `json:"type"` // "make_credential", "get_assertion", "select_account"
	RelyingParty    string           `json:"relyingParty"`
	UserName        string           `json:"userName,omitempty"`
	UserDisplayName string           `json:"userDisplayName,omitempty"`
	Accounts        []AccountPayload `json:"accounts,omitempty"`
}

type AccountPayload struct {
	Index       int    `json:"index"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type ApprovalResponse struct {
	ID            string `json:"id"`
	Approved      bool   `json:"approved"`
	SelectedIndex int    `json:"selectedIndex"`
}

type IdentityDTO struct {
	ID              string `json:"id"`
	RPID            string `json:"rpId"`
	RPName          string `json:"rpName"`
	UserName        string `json:"userName"`
	UserDisplayName string `json:"userDisplayName"`
	SignCount       int32  `json:"signCount"`
}

type Server struct {
	vaultFilename     string
	vaultPassphrase   string
	client            *fido_client.DefaultFIDOClient
	usbipServer       *usbip.USBIPServer
	attachedDriverDir string
	httpServer        *http.Server

	mu         sync.Mutex
	running    bool
	installing bool
	attached   bool
	activePort string

	// Approval coordination
	pendingApprovalMu     sync.Mutex
	pendingApprovals      map[string]chan bool
	pendingSelections     map[string]chan int
	approvalReqDetails    map[string]ApprovalRequestPayload
	lastSelectedAccountID string
	lastSelectedTime      time.Time
	selectionMu           sync.Mutex

	// Log buffering and SSE distribution
	logMu       sync.Mutex
	logs        []LogEntry
	diagnostics []LogEntry
	sseMu       sync.Mutex
	sseClients  map[chan string]bool
}

func NewServer(vaultFile, passphrase string) *Server {
	s := &Server{
		vaultFilename:      vaultFile,
		vaultPassphrase:    passphrase,
		pendingApprovals:   make(map[string]chan bool),
		pendingSelections:  make(map[string]chan int),
		approvalReqDetails: make(map[string]ApprovalRequestPayload),
		logs:               make([]LogEntry, 0, 300),
		sseClients:         make(map[chan string]bool),
	}
	s.initClient()
	return s
}

func (s *Server) initClient() {
	caPrivateKey, err := identities.CreateCAPrivateKey()
	if err != nil {
		panic(err)
	}
	certificateAuthority, err := identities.CreateSelfSignedCA(caPrivateKey)
	if err != nil {
		panic(err)
	}
	encryptionKey := sha256.Sum256([]byte("test"))

	// Pipe virtual_fido logs into Server log distributor
	// Capture first: Windows GUI builds may have no writable stdout handle.
	mw := io.MultiWriter(s, os.Stdout)
	virtual_fido.SetLogOutput(mw)
	virtual_fido.SetLogLevel(util.LogLevelDebug)

	client := fido_client.NewDefaultClient(certificateAuthority, caPrivateKey, encryptionKey, true, s, s)
	client.SetAccountSelector(s)
	s.client = client
}

// io.Writer implementation for capturing logs
func (s *Server) Write(p []byte) (n int, err error) {
	line := string(p)
	lines := strings.Split(line, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		tag := "FIDO"
		msg := trimmed
		if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "]") {
			idx := strings.Index(trimmed, "]")
			tag = strings.Trim(trimmed[1:idx], " ")
			msg = strings.TrimSpace(trimmed[idx+1:])
		}
		entry := LogEntry{
			Time:    time.Now().Format("15:04:05"),
			Tag:     tag,
			Message: msg,
		}

		s.logMu.Lock()
		s.logs = append(s.logs, entry)
		if tag == "DIAGNOSTIC" || (tag == "CTAP" && strings.HasPrefix(msg, "RESULT command=")) {
			s.diagnostics = append(s.diagnostics, entry)
			if len(s.diagnostics) > 300 {
				s.diagnostics = s.diagnostics[1:]
			}
		}
		if len(s.logs) > 300 {
			s.logs = s.logs[1:]
		}
		s.logMu.Unlock()

		data, err := json.Marshal(entry)
		if err == nil {
			s.broadcastSSE("log", string(data))
		}
	}
	return len(p), nil
}

// fido_client.ClientRequestApprover implementation
func (s *Server) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	if action == fido_client.ClientActionFIDOGetAssertion {
		s.selectionMu.Lock()
		recentlySelected := time.Since(s.lastSelectedTime) < 5*time.Second && s.lastSelectedAccountID == params.UserName
		if recentlySelected {
			s.lastSelectedAccountID = ""
			s.selectionMu.Unlock()
			return true
		}
		s.selectionMu.Unlock()
	}

	reqID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	reqType := "make_credential"
	if action == fido_client.ClientActionFIDOGetAssertion {
		reqType = "get_assertion"
	}

	payload := ApprovalRequestPayload{
		ID:              reqID,
		Type:            reqType,
		RelyingParty:    params.RelyingParty,
		UserName:        params.UserName,
		UserDisplayName: params.UserDisplayName,
	}

	respChan := make(chan bool, 1)
	s.pendingApprovalMu.Lock()
	s.pendingApprovals[reqID] = respChan
	s.approvalReqDetails[reqID] = payload
	s.pendingApprovalMu.Unlock()

	data, _ := json.Marshal(payload)
	s.broadcastSSE("approval_request", string(data))

	select {
	case approved := <-respChan:
		return approved
	case <-time.After(60 * time.Second):
		s.pendingApprovalMu.Lock()
		delete(s.pendingApprovals, reqID)
		delete(s.approvalReqDetails, reqID)
		s.pendingApprovalMu.Unlock()
		return false
	}
}

// fido_client.ClientAccountSelector implementation
func (s *Server) SelectAssertionSource(sources []*identities.CredentialSource) *identities.CredentialSource {
	if len(sources) == 0 {
		return nil
	}
	if len(sources) == 1 {
		return sources[0]
	}

	reqID := fmt.Sprintf("select-%d", time.Now().UnixNano())
	accounts := make([]AccountPayload, len(sources))
	for i, src := range sources {
		displayName := src.User.DisplayName
		if displayName == "" {
			displayName = src.User.Name
		}
		accounts[i] = AccountPayload{
			Index:       i,
			ID:          hex.EncodeToString(src.ID),
			Name:        src.User.Name,
			DisplayName: displayName,
		}
	}

	payload := ApprovalRequestPayload{
		ID:           reqID,
		Type:         "select_account",
		RelyingParty: sources[0].RelyingParty.Name,
		Accounts:     accounts,
	}

	respChan := make(chan int, 1)
	s.pendingApprovalMu.Lock()
	s.pendingSelections[reqID] = respChan
	s.approvalReqDetails[reqID] = payload
	s.pendingApprovalMu.Unlock()

	data, _ := json.Marshal(payload)
	s.broadcastSSE("approval_request", string(data))

	select {
	case choice := <-respChan:
		if choice >= 0 && choice < len(sources) {
			s.selectionMu.Lock()
			s.lastSelectedAccountID = sources[choice].User.Name
			s.lastSelectedTime = time.Now()
			s.selectionMu.Unlock()
			return sources[choice]
		}
		return nil
	case <-time.After(60 * time.Second):
		s.pendingApprovalMu.Lock()
		delete(s.pendingSelections, reqID)
		delete(s.approvalReqDetails, reqID)
		s.pendingApprovalMu.Unlock()
		return nil
	}
}

// fido_client.ClientDataSaver implementation
func (s *Server) SaveData(data []byte) {
	f, err := os.CreateTemp(filepath.Dir(s.vaultFilename), ".virtual-fido-vault-*")
	util.CheckErr(err, "Could not create vault file")
	defer os.Remove(f.Name())
	defer f.Close()
	_, err = f.Write(data)
	util.CheckErr(err, "Could not write vault")
	util.CheckErr(f.Sync(), "Could not sync vault")
	util.CheckErr(f.Close(), "Could not close vault")
	util.CheckErr(os.Rename(f.Name(), s.vaultFilename), "Could not replace vault")
	fmt.Fprintln(s, "[DIAGNOSTIC] Vault saved")
	s.broadcastSSE("vault_changed", "{}")
}

func (s *Server) RetrieveData() []byte {
	f, err := os.Open(s.vaultFilename)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return nil
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	return data
}

func (s *Server) Passphrase() string {
	return s.vaultPassphrase
}

// Daemon Start / Stop Lifecycle
func (s *Server) StartDaemon() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.installing {
		return fmt.Errorf("USBip installation is in progress")
	}
	if installedUSBIPDir() == "" {
		err := fmt.Errorf("install the signed USBip driver from Setup & Drivers first")
		fmt.Fprintf(s, "[DIAGNOSTIC] %v\n", err)
		return err
	}
	if s.running {
		// If running, ensure attached
		return s.attachUSBInternal()
	}

	server := virtual_fido.CreateUSBIPServer(s.client)
	s.usbipServer = server
	s.running = true

	go func() {
		server.Start()
		s.mu.Lock()
		s.running = false
		s.attached = false
		s.broadcastStatus()
		s.mu.Unlock()
	}()

	// Allow server socket to listen
	time.Sleep(300 * time.Millisecond)
	err := s.attachUSBInternal()
	s.broadcastStatus()
	return err
}

func (s *Server) StopDaemon() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.detachUSBInternal(); err != nil {
		fmt.Fprintf(s, "[DIAGNOSTIC] Detach failed: %v\n", err)
		return err
	}

	if s.usbipServer != nil {
		s.usbipServer.Stop()
		s.usbipServer = nil
	}
	s.running = false
	s.attached = false
	s.activePort = ""
	s.broadcastStatus()
	return nil
}

func (s *Server) attachUSBInternal() (err error) {
	defer func() {
		if err != nil {
			fmt.Fprintf(s, "[DIAGNOSTIC] Attach failed: %v\n", err)
		}
	}()
	s.queryPortInternal()
	if s.attached {
		return nil
	}
	binDir, modern := usbipBackend()
	args := []string{"attach", "-r", "127.0.0.1", "-b", "2-2", "--terse"}
	if modern {
		args = append(args, "--once")
	}
	out, err := runUSBIP(binDir, args...)
	if err != nil {
		return fmt.Errorf("USB/IP attach failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	port, err := attachedPort(out, modern)
	if err != nil {
		return err
	}
	s.activePort = port
	s.attachedDriverDir = binDir
	s.queryPortInternal()
	if !s.attached {
		return fmt.Errorf("USB/IP port %s did not appear; check the installed driver", port)
	}
	fmt.Fprintf(s, "[DIAGNOSTIC] Attached: backend=%s port=%s\n", backendName(modern), port)
	return nil
}

func (s *Server) detachUSBInternal() error {
	if s.activePort == "" || s.attachedDriverDir == "" {
		return nil
	}
	_, err := runUSBIP(s.attachedDriverDir, "detach", "-p", s.activePort)
	if err != nil {
		return err
	}
	s.attached = false
	s.activePort = ""
	s.attachedDriverDir = ""
	return err
}

func (s *Server) queryPortInternal() {
	s.attached = false
	if s.activePort == "" || s.attachedDriverDir == "" {
		return
	}
	out, err := runUSBIP(s.attachedDriverDir, "port")
	s.attached = err == nil && hasPort(out, s.activePort)
}

// SSE & Status broadcasting
func (s *Server) broadcastSSE(event, data string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", event, data)
	for ch := range s.sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (s *Server) broadcastStatus() {
	s.queryPortInternal()
	status := map[string]interface{}{
		"running":  s.running,
		"attached": s.attached,
		"port":     s.activePort,
		"vault":    s.vaultFilename,
	}
	data, _ := json.Marshal(status)
	s.broadcastSSE("status", string(data))
}

// HTTP Server & Router
func (s *Server) StartHTTPServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(listener)
}

func (s *Server) Serve(listener net.Listener) error {
	defer listener.Close()
	mux := http.NewServeMux()

	// Embedded web assets
	webContent, err := fs.Sub(webFiles, "web")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(webContent))
	mux.Handle("/", fileServer)

	// API routes
	mux.HandleFunc("/api/status", s.apiStatus)
	mux.HandleFunc("/api/start", s.apiStart)
	mux.HandleFunc("/api/stop", s.apiStop)
	mux.HandleFunc("/api/identities", s.apiIdentities)
	mux.HandleFunc("/api/approve", s.apiApprove)
	mux.HandleFunc("/api/pin", s.apiPIN)
	mux.HandleFunc("/api/events", s.apiEvents)
	mux.HandleFunc("/api/diagnostics", s.apiDiagnostics)

	// Installer routes
	mux.HandleFunc("/api/installer/status", s.apiInstallerStatus)
	mux.HandleFunc("/api/installer/driver", s.apiInstallerDriver)
	mux.HandleFunc("/api/installer/uninstall", s.apiInstallerUninstall)
	mux.HandleFunc("/api/installer/diagnose", s.apiInstallerDiagnose)

	s.httpServer = &http.Server{
		Addr:    listener.Addr().String(),
		Handler: mux,
	}

	s.httpServer.Handler = localUIHandler(listener.Addr().String(), mux)

	fmt.Printf("\n[GUI] Virtual FIDO2 Manager running at http://%s\n", listener.Addr().String())
	return s.httpServer.Serve(listener)
}

func backendName(modern bool) string {
	if modern {
		return "usbip-win2"
	}
	return "legacy-test-signed"
}

func (s *Server) apiDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	s.queryPortInternal()
	report := map[string]interface{}{
		"build": "signed-mvp-20261118-approval", "platform": runtime.GOOS, "architecture": runtime.GOARCH,
		"backend": "usbip-win2-signed", "signedInstalled": installedUSBIPDir() != "", "running": s.running, "attached": s.attached, "port": s.activePort,
		"pinEnabled": s.client.SupportsPIN(), "pinConfigured": s.client.PINHash() != nil,
	}
	s.mu.Unlock()
	s.logMu.Lock()
	report["events"] = append([]LogEntry{}, s.diagnostics...)
	s.logMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="virtual-fido-diagnostics.json"`)
	_ = json.NewEncoder(w).Encode(report)
}

// API Handlers
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queryPortInternal()
	res := map[string]interface{}{
		"running":  s.running,
		"attached": s.attached,
		"port":     s.activePort,
		"vault":    s.vaultFilename,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) apiStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := s.StartDaemon()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) apiStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := s.StopDaemon()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) apiIdentities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		sources := s.client.Identities()
		dtos := make([]IdentityDTO, len(sources))
		for i, src := range sources {
			displayName := src.User.DisplayName
			if displayName == "" {
				displayName = src.User.Name
			}
			dtos[i] = IdentityDTO{
				ID:              hex.EncodeToString(src.ID),
				RPID:            src.RelyingParty.ID,
				RPName:          src.RelyingParty.Name,
				UserName:        src.User.Name,
				UserDisplayName: displayName,
				SignCount:       src.SignatureCounter,
			}
		}
		_ = json.NewEncoder(w).Encode(dtos)
		return
	}

	if r.Method == http.MethodDelete {
		idHex := r.URL.Query().Get("id")
		if idHex == "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Missing id"})
			return
		}
		sources := s.client.Identities()
		var target []byte
		for _, src := range sources {
			if hex.EncodeToString(src.ID) == idHex {
				target = src.ID
				break
			}
		}
		if target == nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Identity not found"})
			return
		}
		ok := s.client.DeleteIdentity(target)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": ok})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) apiApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var resp ApprovalResponse
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.pendingApprovalMu.Lock()
	defer s.pendingApprovalMu.Unlock()
	_, approvalPending := s.pendingApprovals[resp.ID]
	_, selectionPending := s.pendingSelections[resp.ID]
	if !approvalPending && !selectionPending {
		fmt.Fprintln(s, "[DIAGNOSTIC] Approval rejected: request expired or already answered")
		http.Error(w, "Request expired or already answered. Retry on the website.", http.StatusGone)
		return
	}

	if ch, ok := s.pendingApprovals[resp.ID]; ok {
		select {
		case ch <- resp.Approved:
		default:
		}
		delete(s.pendingApprovals, resp.ID)
		delete(s.approvalReqDetails, resp.ID)
	}

	if ch, ok := s.pendingSelections[resp.ID]; ok {
		choice := -1
		if resp.Approved {
			choice = resp.SelectedIndex
		}
		select {
		case ch <- choice:
		default:
		}
		delete(s.pendingSelections, resp.ID)
		delete(s.approvalReqDetails, resp.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) apiPIN(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":    s.client.SupportsPIN(),
			"configured": s.client.PINHash() != nil,
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Action string `json:"action"` // "enable", "disable", "set"
			PIN    string `json:"pin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		switch req.Action {
		case "enable":
			s.client.EnablePIN()
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		case "disable":
			s.client.DisablePIN()
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		case "set":
			if !regexp.MustCompile(`^[0-9]{4,8}$`).MatchString(req.PIN) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid PIN (4 to 8 digits required)"})
				return
			}
			s.client.SetPIN([]byte(req.PIN))
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unknown action"})
		}
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan := make(chan string, 32)
	s.sseMu.Lock()
	s.sseClients[clientChan] = true
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, clientChan)
		s.sseMu.Unlock()
	}()

	// Send initial status
	s.mu.Lock()
	s.queryPortInternal()
	status := map[string]interface{}{
		"running":  s.running,
		"attached": s.attached,
		"port":     s.activePort,
		"vault":    s.vaultFilename,
	}
	s.mu.Unlock()
	stData, _ := json.Marshal(status)
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", string(stData))

	// Replay last 20 logs
	s.logMu.Lock()
	startIdx := 0
	if len(s.logs) > 20 {
		startIdx = len(s.logs) - 20
	}
	for _, l := range s.logs[startIdx:] {
		lData, _ := json.Marshal(l)
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", string(lData))
	}
	s.logMu.Unlock()
	flusher.Flush()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg := <-clientChan:
			fmt.Fprint(w, msg)
			flusher.Flush()
		}
	}
}

// The elevated local API must only accept requests addressed to this UI.
func localUIHandler(host string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "Invalid host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Scheme != "http" || u.Host != host {
				http.Error(w, "Invalid origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Installer API Endpoints
func (s *Server) apiInstallerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 3. Check driver
	driverOk, portDetails := checkDriverState()
	s.mu.Lock()
	s.queryPortInternal()
	portsOK := s.attached
	installing := s.installing
	s.mu.Unlock()

	res := map[string]interface{}{
		"driver":          driverOk,
		"portsOk":         portsOK,
		"portDetails":     portDetails,
		"modernBackend":   true,
		"signedInstalled": installedUSBIPDir() != "",
		"installing":      installing,
	}
	_ = json.NewEncoder(w).Encode(res)
}

func getSystemCmd(name string) string {
	windir := os.Getenv("WINDIR")
	if windir != "" {
		sysnative := filepath.Join(windir, "Sysnative", name)
		if _, err := os.Stat(sysnative); err == nil {
			return sysnative
		}
		system32 := filepath.Join(windir, "System32", name)
		if _, err := os.Stat(system32); err == nil {
			return system32
		}
	}
	return name
}

func (s *Server) apiInstallerDriver(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	if s.running || s.installing {
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "output": "Stop the token before installing USBip; another setup must not be running."})
		return
	}
	s.installing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.installing = false; s.mu.Unlock() }()
	err := installSignedDriver()
	output := "Signed USBip installed. Restart Windows, then start the token."
	if err != nil {
		output = err.Error()
	}
	fmt.Fprintf(s, "[DIAGNOSTIC] Signed driver setup: %s\n", output)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         err == nil,
		"output":          output,
		"restartRequired": err == nil,
	})
}

func (s *Server) apiInstallerUninstall(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "output": "Manage USBip through Windows Settings > Apps > Installed apps. Stop the token before changing drivers."})
}

func (s *Server) apiInstallerDiagnose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dir, _ := usbipBackend()
	out, err := runUSBIP(dir, "port")
	output := string(out)
	if err != nil {
		output += err.Error()
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": err == nil, "output": output})
}

// Helpers for checks
func checkDriverState() (bool, string) {
	dir, _ := usbipBackend()
	out, err := runUSBIP(dir, "port")
	if err != nil {
		return false, ""
	}
	if portLine.Match(out) {
		return true, "Imported USB devices present"
	}
	return true, "Driver loaded (Idle)"
}
