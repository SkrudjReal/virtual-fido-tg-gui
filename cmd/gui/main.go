package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bulwarkid/virtual-fido/gui"
)

func launchBrowser(url string) error {
	edgePaths := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}

	for _, p := range edgePaths {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p, fmt.Sprintf("--app=%s", url), "--new-window", "--window-size=1120,800")
			if err := cmd.Start(); err == nil {
				return nil
			}
		}
	}

	// Fallback to default browser
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func runningInstance(url string) bool {
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(url + "/api/diagnostics")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	var info struct{ Build, Backend string }
	if err := json.NewDecoder(io.LimitReader(response.Body, 256*1024)).Decode(&info); err != nil {
		return false
	}
	return strings.HasPrefix(info.Build, "signed-mvp-") && info.Backend == "usbip-win2-signed"
}

func failStartup(err error, noBrowser bool) {
	if noBrowser {
		fmt.Fprintln(os.Stderr, err)
	} else {
		showStartupError(err.Error())
	}
	os.Exit(1)
}

func main() {
	vaultFile := flag.String("vault", "vault.json", "Vault filename")
	passphrase := flag.String("passphrase", "passphrase", "Vault encryption passphrase")
	port := flag.Int("port", 8080, "Web server port")
	noBrowser := flag.Bool("no-browser", false, "Do not auto-open browser window")
	autoStart := flag.Bool("autostart", true, "Automatically start and attach virtual FIDO token on launch")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	url := fmt.Sprintf("http://%s", addr)

	// Reserve the port before opening the vault or starting any background work.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		if runningInstance(url) {
			if !*noBrowser {
				if err := launchBrowser(url); err != nil {
					failStartup(err, false)
				}
			}
			return
		}
		failStartup(fmt.Errorf("Cannot start Virtual FIDO on %s: %w", addr, err), *noBrowser)
		return
	}
	defer listener.Close()

	srv := gui.NewServer(*vaultFile, *passphrase)

	if *autoStart {
		go func() {
			fmt.Println("[GUI] Auto-starting Virtual FIDO2 Token daemon...")
			if err := srv.StartDaemon(); err != nil {
				fmt.Printf("[GUI] Auto-start notice: %v\n", err)
			}
		}()
	}

	if !*noBrowser {
		go func() {
			if err := launchBrowser(url); err != nil {
				showStartupError(err.Error())
			}
		}()
	}

	fmt.Printf("[GUI] Starting Virtual FIDO2 Manager & Setup on %s\n", url)
	if err := srv.Serve(listener); err != nil {
		failStartup(err, *noBrowser)
	}
}
