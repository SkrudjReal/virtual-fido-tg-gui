package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/bulwarkid/virtual-fido/gui"
)

func launchBrowser(url string) {
	edgePaths := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}

	for _, p := range edgePaths {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p, fmt.Sprintf("--app=%s", url), "--window-size=1120,800")
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}

	// Fallback to default browser
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
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

	srv := gui.NewServer(*vaultFile, *passphrase)

	if *autoStart {
		go func() {
			time.Sleep(600 * time.Millisecond)
			fmt.Println("[GUI] Auto-starting Virtual FIDO2 Token daemon...")
			if err := srv.StartDaemon(); err != nil {
				fmt.Printf("[GUI] Auto-start notice: %v\n", err)
			}
		}()
	}

	if !*noBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			launchBrowser(url)
		}()
	}

	fmt.Printf("[GUI] Starting Virtual FIDO2 Manager & Setup on %s\n", url)
	if err := srv.StartHTTPServer(addr); err != nil {
		fmt.Printf("HTTP server error: %v\n", err)
		os.Exit(1)
	}
}
