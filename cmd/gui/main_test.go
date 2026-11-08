package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunningInstance(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       bool
	}{
		{"existing signed GUI", `{"build":"signed-mvp-20261106","backend":"usbip-win2-signed"}`, 200, true},
		{"updated GUI", `{"build":"signed-mvp-20261107-relaunch","backend":"usbip-win2-signed"}`, 200, true},
		{"different application", `{"build":"other","backend":"usbip-win2-signed"}`, 200, false},
		{"wrong backend", `{"build":"signed-mvp-20261106","backend":"other"}`, 200, false},
		{"invalid JSON", `<html>another service</html>`, 200, false},
		{"failed endpoint", `{"build":"signed-mvp-20261106","backend":"usbip-win2-signed"}`, 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/diagnostics" {
					t.Errorf("unexpected probe path: %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			if got := runningInstance(s.URL); got != tc.want {
				t.Fatalf("running=%v, want %v", got, tc.want)
			}
		})
	}
}
