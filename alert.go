package main

import (
	"log"
	"os/exec"
	"sync"
	"time"
)

type Alert struct {
	Time      time.Time
	Severity  Severity
	Operation string // READ, WRITE, DELETE, READDIR, MKDIR
	Path      string // path within canary tree
	Mount     string // mount point on host filesystem
	Message   string
}

type Alerter struct {
	notify   bool
	verbose  bool
	cooldown map[string]time.Time
	mu       sync.Mutex
}

func NewAlerter(notify, verbose bool) *Alerter {
	return &Alerter{
		notify:   notify,
		verbose:  verbose,
		cooldown: make(map[string]time.Time),
	}
}

const alertCooldown = 30 * time.Second

func (a *Alerter) Alert(al Alert) {
	al.Time = time.Now()

	if al.Severity == SevNone {
		return
	}

	a.mu.Lock()
	key := al.Operation + ":" + al.Mount + al.Path
	if last, ok := a.cooldown[key]; ok && time.Since(last) < alertCooldown {
		a.mu.Unlock()
		if a.verbose {
			log.Printf("  (suppressed duplicate: %s %s%s)", al.Operation, al.Mount, al.Path)
		}
		return
	}
	a.cooldown[key] = al.Time
	a.mu.Unlock()

	// Log to stderr
	log.Printf("[%s] %s %s%s - %s",
		al.Severity, al.Operation, al.Mount, al.Path, al.Message)

	// Try to identify accessing process via lsof (best-effort)
	if al.Severity >= SevWarning {
		go a.identifyProcess(al)
	}

	// Desktop notification
	if a.notify && al.Severity >= SevWarning {
		go sendNotification(al)
	}
}

func (a *Alerter) identifyProcess(al Alert) {
	fullPath := al.Mount + al.Path
	out, err := exec.Command("lsof", fullPath).CombinedOutput()
	if err != nil {
		return
	}
	if len(out) > 0 {
		log.Printf("  lsof %s:\n%s", fullPath, out)
	}
}


