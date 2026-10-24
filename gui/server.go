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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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

//go:embed driver_bin/*
var driverFiles embed.FS

func getDriverDir() string {
	// 1. Check local ./cmd/demo/usbip/bin/usbip.exe (source tree dev mode)
	devPath, _ := filepath.Abs(filepath.Join(".", "cmd", "demo", "usbip", "bin"))
	if _, err := os.Stat(filepath.Join(devPath, "usbip.exe")); err == nil {
		return devPath
	}

	// 2. Check local ./bin/usbip.exe (portable folder mode)
	localBin, _ := filepath.Abs(filepath.Join(".", "bin"))
	if _, err := os.Stat(filepath.Join(localBin, "usbip.exe")); err == nil {
		return localBin
	}

	// 3. Fallback to AppData / Local directory: %LOCALAPPDATA%\VirtualFIDO\bin
	appData := os.Getenv("LOCALAPPDATA")
	targetDir := localBin
	if appData != "" {
		targetDir = filepath.Join(appData, "VirtualFIDO", "bin")
	}

	_ = os.MkdirAll(targetDir, 0755)

	// Extract embedded files if usbip.exe is missing
	if _, err := os.Stat(filepath.Join(targetDir, "usbip.exe")); err != nil {
		entries, err := fs.ReadDir(driverFiles, "driver_bin")
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				data, err := driverFiles.ReadFile("driver_bin/" + entry.Name())
				if err == nil {
					_ = os.WriteFile(filepath.Join(targetDir, entry.Name()), data, 0755)
				}
			}
		}
	}
	return targetDir
}

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
	vaultFilename   string
	vaultPassphrase string
	client          *fido_client.DefaultFIDOClient
	usbipServer     *usbip.USBIPServer
	usbAttachCmd    *exec.Cmd
	httpServer      *http.Server

	mu         sync.Mutex
	running    bool
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
	logMu      sync.Mutex
	logs       []LogEntry
	sseMu      sync.Mutex
	sseClients map[chan string]bool
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
	mw := io.MultiWriter(os.Stdout, s)
	virtual_fido.SetLogOutput(mw)
	virtual_fido.SetLogLevel(util.LogLevelDebug)

	client := fido_client.NewDefaultClient(certificateAuthority, caPrivateKey, encryptionKey, false, s, s)
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
		return sources[0]
	case <-time.After(60 * time.Second):
		s.pendingApprovalMu.Lock()
		delete(s.pendingSelections, reqID)
		delete(s.approvalReqDetails, reqID)
		s.pendingApprovalMu.Unlock()
		return sources[0]
	}
}

// fido_client.ClientDataSaver implementation
func (s *Server) SaveData(data []byte) {
	f, err := os.OpenFile(s.vaultFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("SaveData open error: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
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
		s.mu.Unlock()
		s.broadcastStatus()
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

	_ = s.detachUSBInternal()

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

func (s *Server) attachUSBInternal() error {
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")
	if _, err := os.Stat(exePath); err != nil {
		return fmt.Errorf("usbip.exe not found at %s", exePath)
	}

	// First detach any existing ports to avoid conflicts
	_ = s.detachUSBInternal()

	cmd := exec.Command(exePath, "attach", "-r", "127.0.0.1", "-b", "2-2")
	configureCommand(cmd)
	cmd.Dir = binDir
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("attach start failed: %v", err)
	}
	s.usbAttachCmd = cmd

	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		s.attached = false
		s.mu.Unlock()
		s.broadcastStatus()
	}()

	time.Sleep(400 * time.Millisecond)
	s.attached = true
	s.queryPortInternal()
	return nil
}

func (s *Server) detachUSBInternal() error {
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")

	if s.usbAttachCmd != nil && s.usbAttachCmd.Process != nil {
		_ = s.usbAttachCmd.Process.Kill()
		s.usbAttachCmd = nil
	}

	// Detach port 0 or all active ports
	cmd := exec.Command(exePath, "detach", "-p", "0")
	configureCommand(cmd)
	cmd.Dir = binDir
	_, err := cmd.CombinedOutput()
	s.attached = false
	s.activePort = ""
	return err
}

func (s *Server) queryPortInternal() {
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")
	cmd := exec.Command(exePath, "port")
	configureCommand(cmd)
	cmd.Dir = binDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		outStr := string(out)
		if strings.Contains(outStr, "Port 00") || strings.Contains(outStr, "Port 0") {
			s.activePort = "Port 0"
			s.attached = true
		}
	}
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

	// Installer routes
	mux.HandleFunc("/api/installer/status", s.apiInstallerStatus)
	mux.HandleFunc("/api/installer/testsigning", s.apiInstallerTestsigning)
	mux.HandleFunc("/api/installer/cert", s.apiInstallerCert)
	mux.HandleFunc("/api/installer/driver", s.apiInstallerDriver)
	mux.HandleFunc("/api/installer/uninstall", s.apiInstallerUninstall)
	mux.HandleFunc("/api/installer/diagnose", s.apiInstallerDiagnose)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	fmt.Printf("\n[GUI] Virtual FIDO2 Manager running at http://%s\n", listener.Addr().String())
	return s.httpServer.Serve(listener)
}

// API Handlers
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
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

	if ch, ok := s.pendingApprovals[resp.ID]; ok {
		select {
		case ch <- resp.Approved:
		default:
		}
		delete(s.pendingApprovals, resp.ID)
		delete(s.approvalReqDetails, resp.ID)
	}

	if ch, ok := s.pendingSelections[resp.ID]; ok {
		select {
		case ch <- resp.SelectedIndex:
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
		// Placeholder for PIN enabled status
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
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
			pinNum, err := strconv.Atoi(req.PIN)
			if err != nil || pinNum < 0 || len(req.PIN) < 4 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid PIN (4+ digits required)"})
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
	s.queryPortInternal()
	status := map[string]interface{}{
		"running":  s.running,
		"attached": s.attached,
		"port":     s.activePort,
		"vault":    s.vaultFilename,
	}
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

// Installer API Endpoints
func (s *Server) apiInstallerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 1. Check testsigning
	testsigning := checkTestsigningState()

	// 2. Check cert
	certOk := checkCertificateInstalled()

	// 3. Check driver
	driverOk, portDetails := checkDriverState()

	res := map[string]interface{}{
		"testsigning": testsigning,
		"certificate": certOk,
		"driver":      driverOk,
		"portsOk":     driverOk && portDetails != "",
		"portDetails": portDetails,
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

func (s *Server) apiInstallerTestsigning(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cmd := exec.Command(getSystemCmd("bcdedit.exe"), "/set", "testsigning", "on")
	configureCommand(cmd)
	out, err := cmd.CombinedOutput()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(out),
	})
}

func (s *Server) apiInstallerCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	certPath := filepath.Join(getDriverDir(), "usbip_test.pfx")
	cmd := exec.Command(getSystemCmd("certutil.exe"), "-addstore", "-f", "Root", certPath)
	configureCommand(cmd)
	out, err := cmd.CombinedOutput()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(out),
	})
}

func (s *Server) apiInstallerDriver(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")
	cmd := exec.Command(exePath, "install", "-u")
	configureCommand(cmd)
	cmd.Dir = binDir
	out, err := cmd.CombinedOutput()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(out),
	})
}

func (s *Server) apiInstallerUninstall(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")
	cmd := exec.Command(exePath, "uninstall", "-u")
	configureCommand(cmd)
	cmd.Dir = binDir
	out, err := cmd.CombinedOutput()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(out),
	})
}

func (s *Server) apiInstallerDiagnose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")
	cmd := exec.Command(exePath, "port")
	configureCommand(cmd)
	cmd.Dir = binDir
	out, err := cmd.CombinedOutput()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(out),
	})
}

// Helpers for checks
func checkTestsigningState() bool {
	cmd := exec.Command(getSystemCmd("bcdedit.exe"))
	configureCommand(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	re := regexp.MustCompile(`(?i)testsigning\s+yes`)
	return re.Match(out)
}

func checkCertificateInstalled() bool {
	cmd := exec.Command(getSystemCmd("certutil.exe"), "-verifystore", "Root", "USBIP Test")
	configureCommand(cmd)
	return cmd.Run() == nil
}

func checkDriverState() (bool, string) {
	binDir := getDriverDir()
	exePath := filepath.Join(binDir, "usbip.exe")
	cmd := exec.Command(exePath, "port")
	configureCommand(cmd)
	cmd.Dir = binDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, ""
	}
	outStr := string(out)
	if strings.Contains(outStr, "Port") {
		return true, "Port 0 (Imported)"
	}
	return true, "Driver loaded (Idle)"
}
