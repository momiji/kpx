package kpx

import (
	"os"
	"path/filepath"
	"testing"
)

// preserveOptions saves the global options state and restores it after the test.
func preserveOptions(t *testing.T) {
	t.Helper()
	saved := options
	t.Cleanup(func() { options = saved })
}

// writeTempYAML writes content to a temp file in t.TempDir() and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempYAML: %v", err)
	}
	return path
}

// writeTempJSON writes content to a temp .json file and returns its path.
func writeTempJSON(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempJSON: %v", err)
	}
	return path
}

// --- ProxyType ---

func TestProxyTypeName(t *testing.T) {
	cases := []struct {
		pt   ProxyType
		want string
	}{
		{ProxyKerberos, "kerberos"},
		{ProxySocks, "socks"},
		{ProxyAnonymous, "anonymous"},
		{ProxyDirect, "direct"},
		{ProxyBasic, "basic"},
		{ProxyNone, "none"},
		{ProxyPac, "pac"},
	}
	for _, tc := range cases {
		if got := tc.pt.Name(); got != tc.want {
			t.Errorf("ProxyType(%q).Name() = %q, want %q", tc.pt, got, tc.want)
		}
	}
}

func TestProxyTypeValue(t *testing.T) {
	cases := []struct {
		pt   ProxyType
		want int
	}{
		{ProxyKerberos, 0},
		{ProxySocks, 1},
		{ProxyAnonymous, 2},
		{ProxyDirect, 3},
		{ProxyBasic, 4},
		{ProxyNone, 5},
		{ProxyPac, 6},
		{ProxyType("unknown"), -1},
		{ProxyType(""), -1},
	}
	for _, tc := range cases {
		if got := tc.pt.Value(); got != tc.want {
			t.Errorf("ProxyType(%q).Value() = %d, want %d", tc.pt, got, tc.want)
		}
	}
}

func TestProxyTypeNameValueRoundtrip(t *testing.T) {
	all := []ProxyType{ProxyKerberos, ProxySocks, ProxyAnonymous, ProxyDirect, ProxyBasic, ProxyNone, ProxyPac}
	seen := map[int]ProxyType{}
	for _, pt := range all {
		v := pt.Value()
		if v == -1 {
			t.Errorf("ProxyType(%q).Value() returned -1 unexpectedly", pt)
		}
		if other, dup := seen[v]; dup {
			t.Errorf("duplicate Value() %d for %q and %q", v, pt, other)
		}
		seen[v] = pt
		if pt.Name() != string(pt) {
			t.Errorf("Name() = %q, want %q", pt.Name(), string(pt))
		}
	}
}

// --- ConfRule methods ---

func TestConfRuleFirstProxy_Single(t *testing.T) {
	p := "myproxy"
	r := ConfRule{Proxy: &p}
	if got := r.firstProxy(); got != "myproxy" {
		t.Errorf("firstProxy() = %q, want myproxy", got)
	}
}

func TestConfRuleFirstProxy_Multi(t *testing.T) {
	p := "alpha,beta,gamma"
	r := ConfRule{Proxy: &p}
	if got := r.firstProxy(); got != "alpha" {
		t.Errorf("firstProxy() = %q, want alpha (first of comma list)", got)
	}
}

func TestConfRuleAllProxiesName_Single(t *testing.T) {
	p := "only"
	r := ConfRule{Proxy: &p}
	got := r.allProxiesName()
	if len(got) != 1 || got[0] != "only" {
		t.Errorf("allProxiesName() = %v, want [only]", got)
	}
}

func TestConfRuleAllProxiesName_Multi(t *testing.T) {
	p := "alpha,beta,gamma"
	r := ConfRule{Proxy: &p}
	got := r.allProxiesName()
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("allProxiesName() len = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("allProxiesName()[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// --- readConfFromFile ---

func TestReadConfFromFile_YAML(t *testing.T) {
	path := writeTempYAML(t, `
bind: 1.2.3.4
port: 9999
verbose: true
connectTimeout: 30
rules:
  - host: "*.example.com"
    proxy: myproxy
proxies:
  myproxy:
    type: anonymous
    host: proxy.example.com
    port: 8080
`)
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.Bind != "1.2.3.4" {
		t.Errorf("Bind = %q, want 1.2.3.4", conf.Bind)
	}
	if conf.Port != 9999 {
		t.Errorf("Port = %d, want 9999", conf.Port)
	}
	if !conf.Verbose {
		t.Error("Verbose = false, want true")
	}
	if conf.ConnectTimeout != 30 {
		t.Errorf("ConnectTimeout = %d, want 30", conf.ConnectTimeout)
	}
	if len(conf.Rules) != 1 || *conf.Rules[0].Host != "*.example.com" {
		t.Errorf("unexpected Rules: %v", conf.Rules)
	}
	if p := conf.Proxies["myproxy"]; p == nil {
		t.Error("proxy 'myproxy' not found")
	} else if p.Port != 8080 {
		t.Errorf("proxy port = %d, want 8080", p.Port)
	}
}

func TestReadConfFromFile_YAMLAlternateTags(t *testing.T) {
	path := writeTempYAML(t, `
socksPort: 1080
connectTimeout: 5
idleTimeout: 60
closeTimeout: 15
ui: true
socksRules:
  - host: "10.0.0.*"
    proxy: direct
`)
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.SocksPort != 1080 {
		t.Errorf("SocksPort = %d, want 1080", conf.SocksPort)
	}
	if conf.ConnectTimeout != 5 {
		t.Errorf("ConnectTimeout = %d, want 5", conf.ConnectTimeout)
	}
	if conf.IdleTimeout != 60 {
		t.Errorf("IdleTimeout = %d, want 60", conf.IdleTimeout)
	}
	if conf.CloseTimeout != 15 {
		t.Errorf("CloseTimeout = %d, want 15", conf.CloseTimeout)
	}
	if !conf.ConsoleUI {
		t.Error("ConsoleUI (yaml:ui) = false, want true")
	}
	if len(conf.SocksRules) != 1 {
		t.Errorf("SocksRules len = %d, want 1", len(conf.SocksRules))
	}
}

func TestReadConfFromFile_JSON(t *testing.T) {
	path := writeTempJSON(t, `{"bind":"5.6.7.8","port":7777,"connectTimeout":20,"verbose":true}`)
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.Bind != "5.6.7.8" {
		t.Errorf("Bind = %q, want 5.6.7.8", conf.Bind)
	}
	if conf.Port != 7777 {
		t.Errorf("Port = %d, want 7777", conf.Port)
	}
	if conf.ConnectTimeout != 20 {
		t.Errorf("ConnectTimeout = %d, want 20", conf.ConnectTimeout)
	}
	if !conf.Verbose {
		t.Error("Verbose = false, want true")
	}
}

func TestReadConfFromFile_DefaultTimeouts(t *testing.T) {
	// File specifies no timeout fields; defaults must be applied.
	path := writeTempYAML(t, `bind: 0.0.0.0`)
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.ConnectTimeout != DEFAULT_CONNECT_TIMEOUT {
		t.Errorf("ConnectTimeout = %d, want default %d", conf.ConnectTimeout, DEFAULT_CONNECT_TIMEOUT)
	}
	if conf.IdleTimeout != DEFAULT_IDLE_TIMOUT {
		t.Errorf("IdleTimeout = %d, want default %d", conf.IdleTimeout, DEFAULT_IDLE_TIMOUT)
	}
	if conf.CloseTimeout != DEFAULT_CLOSE_TIMEOUT {
		t.Errorf("CloseTimeout = %d, want default %d", conf.CloseTimeout, DEFAULT_CLOSE_TIMEOUT)
	}
}

func TestReadConfFromFile_FileNotFound(t *testing.T) {
	_, err := readConfFromFile("/no/such/file.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestReadConfFromFile_InvalidYAML(t *testing.T) {
	path := writeTempYAML(t, "bind: [\nbroken")
	_, err := readConfFromFile(path)
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestReadConfFromFile_InvalidJSON(t *testing.T) {
	path := writeTempJSON(t, `{ not valid json`)
	_, err := readConfFromFile(path)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestReadConfFromFile_ListenOverride(t *testing.T) {
	preserveOptions(t)
	options.Listen = "10.0.0.1:4444"

	path := writeTempYAML(t, "bind: 0.0.0.0\nport: 8080")
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.Bind != "10.0.0.1" {
		t.Errorf("Bind = %q, want 10.0.0.1 (from --listen)", conf.Bind)
	}
	if conf.Port != 4444 {
		t.Errorf("Port = %d, want 4444 (from --listen)", conf.Port)
	}
}

func TestReadConfFromFile_UserFillsMissingLogin(t *testing.T) {
	// Credential has a password but no login: --user should supply the login and clear the password.
	preserveOptions(t)
	options.User = "alice"

	path := writeTempYAML(t, `
credentials:
  svc:
    password: stale-secret
`)
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := conf.Credentials["svc"]
	if cred == nil {
		t.Fatal("credential 'svc' not found")
	}
	if cred.Login == nil || *cred.Login != "alice" {
		t.Errorf("Login = %v, want alice", cred.Login)
	}
	if cred.Password != nil {
		t.Errorf("Password should be cleared when --user fills login, got %q", *cred.Password)
	}
}

func TestReadConfFromFile_UserSkipsExistingLogin(t *testing.T) {
	// Credential already has a login: --user must not override it.
	preserveOptions(t)
	options.User = "alice"

	path := writeTempYAML(t, `
credentials:
  svc:
    login: bob
    password: correct-secret
`)
	conf, err := readConfFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := conf.Credentials["svc"]
	if cred == nil {
		t.Fatal("credential 'svc' not found")
	}
	if cred.Login == nil || *cred.Login != "bob" {
		t.Errorf("Login = %v, want bob (existing login must not be overridden by --user)", cred.Login)
	}
}

// --- readConfFromOptions ---

func TestReadConfFromOptions_Direct(t *testing.T) {
	preserveOptions(t)
	options = Options{bindHost: "127.0.0.1", bindPort: 8080, proxyPort: 0}

	conf := readConfFromOptions()

	if conf.Bind != "127.0.0.1" {
		t.Errorf("Bind = %q, want 127.0.0.1", conf.Bind)
	}
	if conf.Port != 8080 {
		t.Errorf("Port = %d, want 8080", conf.Port)
	}
	if len(conf.Proxies) != 0 {
		t.Errorf("Proxies len = %d, want 0 for direct mode", len(conf.Proxies))
	}
	if len(conf.Rules) != 1 {
		t.Fatalf("Rules len = %d, want 1", len(conf.Rules))
	}
	if *conf.Rules[0].Proxy != "direct" {
		t.Errorf("Rules[0].Proxy = %q, want direct", *conf.Rules[0].Proxy)
	}
	if *conf.Rules[0].Host != "*" {
		t.Errorf("Rules[0].Host = %q, want *", *conf.Rules[0].Host)
	}
}

func TestReadConfFromOptions_Anonymous(t *testing.T) {
	preserveOptions(t)
	options = Options{
		bindHost:  "127.0.0.1",
		bindPort:  8080,
		proxyHost: "proxy.corp.com",
		proxyPort: 3128,
		login:     "", // no login → anonymous
	}

	conf := readConfFromOptions()

	p := conf.Proxies["proxy"]
	if p == nil {
		t.Fatal("proxy 'proxy' not found")
	}
	if p.Type == nil || *p.Type != ProxyAnonymous {
		t.Errorf("Type = %v, want ProxyAnonymous", p.Type)
	}
	if p.Host == nil || *p.Host != "proxy.corp.com" {
		t.Errorf("Host = %v, want proxy.corp.com", p.Host)
	}
	if p.Port != 3128 {
		t.Errorf("Port = %d, want 3128", p.Port)
	}
	if len(conf.Credentials) != 0 {
		t.Errorf("Credentials len = %d, want 0 for anonymous proxy", len(conf.Credentials))
	}
	if *conf.Rules[0].Proxy != "proxy" {
		t.Errorf("Rules[0].Proxy = %q, want proxy", *conf.Rules[0].Proxy)
	}
}

func TestReadConfFromOptions_Kerberos(t *testing.T) {
	preserveOptions(t)
	options = Options{
		bindHost:  "127.0.0.1",
		bindPort:  8080,
		proxyHost: "proxy.corp.com",
		proxyPort: 3128,
		login:     "jdoe",
		domain:    "CORP.COM",
	}

	conf := readConfFromOptions()

	p := conf.Proxies["proxy"]
	if p == nil {
		t.Fatal("proxy 'proxy' not found")
	}
	if p.Type == nil || *p.Type != ProxyKerberos {
		t.Errorf("Type = %v, want ProxyKerberos", p.Type)
	}
	if p.Realm == nil || *p.Realm != "CORP.COM" {
		t.Errorf("Realm = %v, want CORP.COM", p.Realm)
	}
	if p.Spn == nil || *p.Spn != "HTTP" {
		t.Errorf("Spn = %v, want HTTP", p.Spn)
	}
	if p.Credential == nil || *p.Credential != "user" {
		t.Errorf("Credential = %v, want user", p.Credential)
	}

	cred := conf.Credentials["user"]
	if cred == nil {
		t.Fatal("credential 'user' not found")
	}
	if cred.Login == nil || *cred.Login != "jdoe" {
		t.Errorf("Login = %v, want jdoe", cred.Login)
	}

	if *conf.Rules[0].Proxy != "proxy" {
		t.Errorf("Rules[0].Proxy = %q, want proxy", *conf.Rules[0].Proxy)
	}
}

func TestReadConfFromOptions_ACL(t *testing.T) {
	preserveOptions(t)
	options = Options{ACL: "192.168.1.0/24,10.0.0.1"}

	conf := readConfFromOptions()

	if len(conf.ACL) != 2 {
		t.Fatalf("ACL len = %d, want 2", len(conf.ACL))
	}
	if conf.ACL[0] != "192.168.1.0/24" || conf.ACL[1] != "10.0.0.1" {
		t.Errorf("ACL = %v, want [192.168.1.0/24 10.0.0.1]", conf.ACL)
	}
}

func TestReadConfFromOptions_EmptyACL(t *testing.T) {
	preserveOptions(t)
	options = Options{}

	conf := readConfFromOptions()

	if conf.ACL != nil {
		t.Errorf("ACL = %v, want nil when not set", conf.ACL)
	}
}

func TestReadConfFromOptions_DefaultTimeouts(t *testing.T) {
	preserveOptions(t)
	options = Options{}

	conf := readConfFromOptions()

	if conf.ConnectTimeout != DEFAULT_CONNECT_TIMEOUT {
		t.Errorf("ConnectTimeout = %d, want %d", conf.ConnectTimeout, DEFAULT_CONNECT_TIMEOUT)
	}
	if conf.IdleTimeout != DEFAULT_IDLE_TIMOUT {
		t.Errorf("IdleTimeout = %d, want %d", conf.IdleTimeout, DEFAULT_IDLE_TIMOUT)
	}
	if conf.CloseTimeout != DEFAULT_CLOSE_TIMEOUT {
		t.Errorf("CloseTimeout = %d, want %d", conf.CloseTimeout, DEFAULT_CLOSE_TIMEOUT)
	}
}
