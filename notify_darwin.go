//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func consoleUser() string {
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func sendNotification(al Alert) {
	title := fmt.Sprintf("Canary [%s]", al.Severity)
	msg := fmt.Sprintf("%s: %s%s", al.Operation, al.Mount, al.Path)
	script := fmt.Sprintf(
		`display notification %q with title %q sound name "Sosumi"`,
		msg, title)

	if os.Getuid() == 0 {
		user := consoleUser()
		if user == "" || user == "root" {
			return
		}
		exec.Command("sudo", "-u", user, "osascript", "-e", script).Run()
	} else {
		exec.Command("osascript", "-e", script).Run()
	}
}

func validateNotifyBinary() error {
	return nil
}
