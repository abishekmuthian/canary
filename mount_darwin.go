//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"log"
)

const (
	defaultMode     = "webdav"
	webDAVSupported = true
)

func mountWebDAV(url, mountPoint string) error {
	cmd := exec.Command("mount_webdav", "-S", url, mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v %s", err, string(out))
	}
	return nil
}

func mountNFS(port int, mountPoint string) error {
	mountArgs := fmt.Sprintf("vers=3,tcp,port=%d,mountport=%d,locallocks,noresvport", port, port)
	cmd := exec.Command("mount_nfs", "-o", mountArgs, "localhost:/canary", mountPoint)
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
			exec.Command("diskutil", "unmount", "force", mp).Run()
		} else {
			log.Printf("unmounted: %s", mp)
		}
	}
}
