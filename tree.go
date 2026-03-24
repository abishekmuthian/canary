package main

import (
	"path"
	"strings"
	"time"
)

type Severity int

const (
	SevNone Severity = iota
	SevInfo
	SevWarning
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevWarning:
		return "WARNING"
	case SevInfo:
		return "INFO"
	default:
		return "NONE"
	}
}

type VNode struct {
	Name     string
	IsDir    bool
	Content  []byte
	Children []*VNode
	ModTime  time.Time
	Severity Severity
}

func Dir(name string, t time.Time, children ...*VNode) *VNode {
	return &VNode{Name: name, IsDir: true, ModTime: t, Children: children}
}

func File(name string, t time.Time, sev Severity, content string) *VNode {
	return &VNode{Name: name, Content: []byte(content), ModTime: t, Severity: sev}
}

func (n *VNode) Lookup(name string) *VNode {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (n *VNode) Resolve(reqPath string) *VNode {
	reqPath = path.Clean(reqPath)
	if reqPath == "/" || reqPath == "." {
		return n
	}
	parts := strings.Split(strings.TrimPrefix(reqPath, "/"), "/")
	cur := n
	for _, p := range parts {
		cur = cur.Lookup(p)
		if cur == nil {
			return nil
		}
	}
	return cur
}

// DefaultTree returns enticing canary files that look like accidentally
// exposed secrets. Edit this function to customize your honeypot.
func DefaultTree() *VNode {
	// Backdate files so they look like they've been sitting here a while
	t := time.Now().Add(-7 * 24 * time.Hour)

	return Dir("", t,
		// Suppress Spotlight indexing (not a canary, no alert)
		File(".metadata_never_index", t, SevNone, ""),

		File(".env", t, SevCritical,
			`# Production environment - DO NOT COMMIT
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://admin:s3cret_pr0d_passw0rd@db.internal:5432/production
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
OPENAI_API_KEY=sk-canary-do-not-use-this-key-1234567890abcdef
`),

		File("id_rsa", t, SevCritical,
			`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBwSjsK4rXnEBlyJOPtnXGBJqwmOPSJBRwxyTaFCRlYDAAAAJhEGI+ERBiP
hAAAAAtzc2gtZWQyNTUxOQAAACBwSjsK4rXnEBlyJOPtnXGBJqwmOPSJBRwxyTaFCRlYDA
AAAED0CANARY0TOKEN0NOT0REAL0KEY0MATERIAL0AAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAACBwSjsK4rXnEBlyJOPtnXGBJqwmOPSJBRwxyTaFCRlYDAAAADnJvb3RAcHJvZC1i
YXN0aW9uAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`),

		File("credentials.json", t, SevCritical,
			`{
  "type": "service_account",
  "project_id": "prod-infrastructure-391204",
  "private_key_id": "canary-key-do-not-use",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nCANARY-NOT-A-REAL-KEY\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "deployer@prod-infrastructure-391204.iam.gserviceaccount.com",
  "client_id": "118293745610293847561",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
`),

		File(".npmrc", t, SevCritical,
			`//registry.npmjs.org/:_authToken=npm_CANARY000000000000000000000000000000
@company:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_canary0000000000000000000000000000
`),

		File(".git-credentials", t, SevCritical,
			`https://deploy-bot:ghp_canary0000000000000000000000000000@github.com
https://admin:glpat-canary00000000000000@gitlab.company.com
`),

		Dir("config", t,
			File("kubeconfig", t, SevCritical,
				`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.internal:6443
    certificate-authority-data: LS0tLS1CRUdJTi...CANARY
  name: prod-cluster
contexts:
- context:
    cluster: prod-cluster
    user: admin
  name: prod
current-context: prod
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImNhbmFyeSJ9.CANARY_TOKEN
`),

			File("database.yml", t, SevCritical,
				`production:
  adapter: postgresql
  host: prod-primary.db.internal
  database: app_production
  username: app_admin
  password: "pr0d_db_p@ssw0rd_2024!"
  pool: 25
`),
		),

		File("backup.sql.gz", t.Add(-30*24*time.Hour), SevWarning,
			"(binary data - this is a canary, not a real backup)"),

		File("token.txt", t, SevCritical,
			"xoxb-canary-000000000000-0000000000000-CanaryTokenSlackBot\n"),
	)
}
