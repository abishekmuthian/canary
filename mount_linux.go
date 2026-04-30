//go:build linux

package main

import (
	"fmt"
	"log"
	"os/exec"
)

const (
	defaultMode     = "nfs"
	webDAVSupported = false
)

// mountWebDAV is unreachable on Linux (webDAVSupported is false; main rejects
// -mode webdav before runWebDAV runs). It exists only to satisfy the build.
func mountWebDAV(url, mountPoint string) error {
	return fmt.Errorf("webdav mode is not supported on Linux")
}

func mountNFS(port int, mountPoint string) error {
	mountArgs := fmt.Sprintf("vers=3,tcp,port=%d,mountport=%d,nolock", port, port)
	cmd := exec.Command("mount", "-t", "nfs", "-o", mountArgs, "localhost:/canary", mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v %s", err, string(out))
	}
	return nil
}

func unmountAll(mounts []string) {
	for _, mp := range mounts {
		if err := exec.Command("umount", mp).Run(); err != nil {
			log.Printf("unmount %s: %v (trying force)", mp, err)
			exec.Command("umount", "-f", mp).Run()
		} else {
			log.Printf("unmounted: %s", mp)
		}
	}
}
