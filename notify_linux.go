//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

// guiUser returns the username and uid of the logged-in desktop user, or
// empty strings if no graphical session is detected.
func guiUser() (string, string) {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil {
			return name, u.Uid
		}
	}

	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		sessionID := fields[0]
		name := fields[2]
		if name == "" || name == "root" {
			continue
		}
		props, err := exec.Command("loginctl", "show-session", sessionID,
			"-p", "Type", "-p", "State").Output()
		if err != nil {
			continue
		}
		text := string(props)
		if !strings.Contains(text, "State=active") {
			continue
		}
		if !strings.Contains(text, "Type=x11") && !strings.Contains(text, "Type=wayland") {
			continue
		}
		if u, err := user.Lookup(name); err == nil {
			return name, u.Uid
		}
	}
	return "", ""
}

func sendNotification(al Alert) {
	title := fmt.Sprintf("Canary [%s]", al.Severity)
	msg := fmt.Sprintf("%s: %s%s", al.Operation, al.Mount, al.Path)

	if os.Getuid() == 0 {
		name, uid := guiUser()
		if name == "" {
			log.Printf("notify: no graphical session detected (SUDO_USER=%q); skipping desktop notification", os.Getenv("SUDO_USER"))
			return
		}
		runtimeDir := fmt.Sprintf("/run/user/%s", uid)
		// sudo's default env_reset strips DBUS_SESSION_BUS_ADDRESS/XDG_RUNTIME_DIR
		// from the parent env, so set them via `env` inside the target user's shell.
		cmd := exec.Command("sudo", "-u", name, "env",
			"DBUS_SESSION_BUS_ADDRESS=unix:path="+runtimeDir+"/bus",
			"XDG_RUNTIME_DIR="+runtimeDir,
			"notify-send", title, msg)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("notify-send failed (user=%s): %v: %s", name, err, strings.TrimSpace(string(out)))
		}
	} else {
		if err := exec.Command("notify-send", title, msg).Run(); err != nil {
			log.Printf("notify-send failed: %v", err)
		}
	}
}

func validateNotifyBinary() error {
	if _, err := exec.LookPath("notify-send"); err != nil {
		return fmt.Errorf("notify-send not found; install libnotify (e.g., apt install libnotify-bin, dnf install libnotify)")
	}
	return nil
}
