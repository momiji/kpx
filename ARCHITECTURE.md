# Modular Architecture — KPX v2

## Context

KPX is an authenticating HTTP/SOCKS proxy (Kerberos, Basic, SOCKS) with hot configuration reload, JavaScript PAC support, TLS certificate generation for MITM, and an optional TUI interface.

### Problems with the current structure

| File | Lines | Problem |
|---|---|---|
| `config.go` | ~2500 | Does everything: parsing, validation, PAC generation, cert generation, rule matching |
| `process.go` | ~2000 | Does everything: HTTP loop, authentication, CONNECT tunneling, local server |
| `proxy.go` | ~800 | Mixed: TCP server, connection pool, reload, watchers |
| All in `package kpx` | — | Invisible boundaries, impossible to test a component in isolation |

---

## Target Architecture

### Overview

```
kpx/
├── main.go                    # Entry point (< 20 lines)
├── global.go                  # Global constants, CLI Options
│
├── config/                    # Configuration loading and validation
│   ├── config.go              # Config, Conf types, loaders (YAML/CLI)
│   ├── rule.go                # Rule matching (matchHttp, matchSocks, HostCache)
│   ├── validate.go            # Validation and construction (check, build)
│   └── pac_gen.go             # proxy.pac file generation
│
├── proxy/                     # Proxy server and lifecycle
│   ├── proxy.go               # Proxy struct, start(), stop()
│   ├── reload.go              # Hot reload (watch1, watch2, reload)
│   └── pool.go                # Upstream connection pool (connPool)
│
├── handler/                   # Request processing (pipeline)
│   ├── process.go             # Process struct, main loop processHttp()
│   ├── http.go                # Standard HTTP processing (processChannel)
│   ├── connect.go             # CONNECT tunnel / HTTPS (processConnect)
│   └── local.go               # Local web server (/proxy.pac, /status)
│
├── auth/                      # Upstream authentication
│   ├── auth.go                # Authenticator interface
│   ├── kerberos.go            # Kerberos auth (SPNEGO/Negotiate)
│   ├── basic.go               # Basic auth (base64)
│   └── store.go               # KerberosStore: multi-client Kerberos management
│
├── transport/                 # Low-level network layer
│   ├── conn.go                # TimedConn, CloseAwareConn
│   └── chunked.go             # chunkedReader (HTTP chunked decoding)
│
├── cert/                      # TLS certificate management
│   ├── cert.go                # Certificate generation (RSA, X.509)
│   └── manager.go             # CertsManager: cache and wildcards
│
├── pac/                       # PAC file execution (JavaScript)
│   └── pac.go                 # PacExecutor, pool of goja runtimes
│
├── log/                       # Logging
│   └── log.go                 # Init, levels, sensitive header masking
│
├── utils/                     # Shared utilities
│   ├── mre.go                 # ManualResetEvent (goroutine synchronization)
│   └── password.go            # Password encryption
│
├── ui/                        # TUI / console interface (existing)
│   ├── ui.go
│   ├── ui_data.go
│   ├── ui_tui.go
│   └── ui_tconsole.go
│
└── term/                      # Terminal abstraction (existing)
```

---

## Module Descriptions

### `config/` — Configuration

**Single responsibility**: load, validate, and expose configuration.

```go
// config/config.go
package config

type Config struct {
    Conf       *Conf
    PacCache   *pac.PacExecutor    // injected after build
    CertMgr    *cert.CertsManager  // injected after build
    HostsCache sync.Map
}

type Conf struct {
    Proxies     map[string]*ConfProxy
    Credentials map[string]*ConfCred
    Rules       []*ConfRule
    Domains     map[string]string
    ACL         []string
    Listen      string
    // ...
}

func Load(path string) (*Config, error)              // from file
func LoadFromOptions(opts *Options) (*Config, error) // from CLI
```

```go
// config/rule.go
package config

func (c *Config) MatchHttp(host string, port int) (*ConfRule, *ConfProxy)
func (c *Config) MatchSocks(host string, port int) (*ConfRule, *ConfProxy)
```

```go
// config/validate.go
package config

func (c *Config) Validate() error
func (c *Config) Build() error
```

**What moves out of the current config.go**: PAC generation goes to `config/pac_gen.go`, cert generation goes to `cert/`, rule matching goes to `config/rule.go`.

---

### `proxy/` — Server and Lifecycle

**Responsibility**: listen for incoming connections, manage config reload.

```go
// proxy/proxy.go
package proxy

type Proxy struct {
    config  atomic.Pointer[config.Config]
    auth    *auth.Store
    pool    *pool.ConnPool
    stop    *util.ManualResetEvent
}

func New() *Proxy
func (p *Proxy) Load(opts *Options) error
func (p *Proxy) Start(ctx context.Context) error
func (p *Proxy) Stop()
```

```go
// proxy/pool.go
package proxy

type ConnPool struct {
    mu    sync.Mutex
    conns map[string]*list.List  // key: upstream proxy name
}

func (cp *ConnPool) Get(proxy string) (net.Conn, bool)
func (cp *ConnPool) Put(proxy string, conn net.Conn)
func (cp *ConnPool) Evict(proxy string)
```

---

### `handler/` — Processing Pipeline

**Responsibility**: handle a client connection end-to-end.

```go
// handler/process.go
package handler

type Process struct {
    id      uint64
    cfg     *config.Config
    client  *transport.TimedConn
    log     *log.TraceInfo
    traffic *ui.TrafficRow
}

func New(conn net.Conn, cfg *config.Config, pool *proxy.ConnPool) *Process
func (p *Process) Run()
```

```go
// handler/http.go
package handler

// Handles a simple HTTP request
func (p *Process) handleRequest(req *request.ProxyRequest) error

// handler/connect.go
// CONNECT tunnel
func (p *Process) handleConnect(req *request.ProxyRequest) error

// handler/local.go
// Local server (/proxy.pac, /status, /reload)
func (p *Process) handleLocal(req *request.ProxyRequest) error
```

---

### `auth/` — Authentication

**Responsibility**: abstract upstream authentication mechanisms.

```go
// auth/auth.go
package auth

// Common interface for all mechanisms
type Authenticator interface {
    // Computes the Proxy-Authorization header value
    Authorize(req *http.Request, challenge string) (string, error)
    // Scheme name (Negotiate, Basic, ...)
    Scheme() string
}

func New(proxy *config.ConfProxy, cred *config.ConfCred) (Authenticator, error)
```

```go
// auth/store.go
package auth

// Manages Kerberos clients (native OS login or user/password)
type Store struct {
    mu      sync.Mutex
    clients map[string]*KerberosClient
}

func NewStore() *Store
func (s *Store) GetOrCreate(realm, user, pass string) (*KerberosClient, error)
func (s *Store) LoadNative(conf *config.Config) error
```

---

### `transport/` — Network Layer

**Responsibility**: reusable network abstractions.

```go
// transport/conn.go
package transport

type TimedConn struct { /* net.Conn + timeouts */ }
type CloseAwareConn struct { /* remote close detection */ }

func NewTimed(conn net.Conn, timeout time.Duration) *TimedConn
func NewCloseAware(conn net.Conn) *CloseAwareConn
func Configure(conn net.Conn) error  // TCP_NODELAY
```

---

### `cert/` — TLS Certificates

**Responsibility**: X.509 certificate generation and caching.

```go
// cert/cert.go
package cert

type Cert struct {
    Priv *rsa.PrivateKey
    Pub  *x509.Certificate
}

func New(ca *Cert, template *x509.Certificate) (*Cert, error)
func NewCA() (*Cert, error)
func FromFiles(certFile, keyFile string) (*Cert, error)
func (c *Cert) Save(certFile, keyFile string) error

// cert/manager.go
type Manager struct {
    ca     *Cert
    cache  map[string]*tls.Certificate
    mu     sync.RWMutex
}

func NewManager(ca *Cert, prefix string) *Manager
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
```

---

### `pac/` — JavaScript PAC

**Responsibility**: compile and execute PAC files.

```go
// pac/pac.go
package pac

type Executor struct {
    program *goja.Program
    pool    sync.Pool
}

func New(script string) (*Executor, error)
func (e *Executor) Run(url, host string) (string, error)
```

---

### `crypto/` — Encryption

**Responsibility**: encrypt/decrypt config passwords.

```go
// crypto/crypto.go
package crypto

func Encrypt(password string) (string, error)
func Decrypt(encoded string) (string, error)
func IsEncrypted(s string) bool
func InteractiveEncrypt() error  // interactive CLI
```

---

### `util/` — Utilities

```go
// util/mre.go
package util

type ManualResetEvent struct { /* ... */ }

func New(signaled bool) *ManualResetEvent
func (e *ManualResetEvent) Signal()
func (e *ManualResetEvent) Reset()
func (e *ManualResetEvent) Wait()
func (e *ManualResetEvent) WaitContext(ctx context.Context) error
```

---

## Dependency Diagram

```
main.go
  └── proxy/proxy.go
        ├── config/           (loading + matching)
        │     ├── pac/        (proxy.pac generation)
        │     └── cert/       (certificate generation)
        ├── handler/          (request processing)
        │     ├── auth/       (upstream authentication)
        │     ├── transport/  (network connections)
        │     ├── config/     (rules, lookup)
        │     └── ui/         (traffic stats)
        ├── auth/store        (Kerberos sessions)
        ├── crypto/           (password decryption)
        ├── log/              (logging)
        └── util/             (MRE, synchronization)

ui/     ← no dependency toward kpx (one-way)
term/   ← no dependency toward kpx (one-way)
```

**Fundamental rule**: dependencies always flow downward. `handler` knows about `config` and `auth`, but `config` does not know about `handler`.

---

## Migration Strategy

Migration happens **file by file**, in this priority order:

### Phase 1 — Foundations (no risk)
1. `util/mre.go` ← extract `mre.go`
2. `transport/conn.go` ← extract `conn.go`
3. `transport/chunked.go` ← extract `chunked.go`
4. `crypto/crypto.go` ← extract `password.go`
5. `log/log.go` ← extract `log.go`

### Phase 2 — Isolated Domains
6. `pac/pac.go` ← extract `pac.go`
7. `cert/cert.go` + `cert/manager.go` ← extract `certs.go` + `certs_manager.go`
8. `auth/kerberos.go` + `auth/store.go` ← extract `kerberos.go` + `kerberos_store.go`
9. `auth/basic.go` ← extract Basic logic from `process.go`

### Phase 3 — Configuration (main work)
10. `config/rule.go` ← extract `matchHttp`, `matchSocks`, `HostCache` from `config.go`
11. `config/validate.go` ← extract `check()`, `build()` from `config.go`
12. `config/pac_gen.go` ← extract `genPac()` from `config.go`
13. `config/config.go` ← whatever remains

### Phase 4 — Handler (main work)
14. `handler/local.go` ← extract `webServer()` from `process.go`
15. `handler/connect.go` ← extract `processConnect()` from `process.go`
16. `handler/http.go` ← extract `processChannel()` from `process.go`
17. `handler/process.go` ← whatever remains of `process.go`

### Phase 5 — Proxy
18. `proxy/pool.go` ← extract `connPool` from `proxy.go`
19. `proxy/reload.go` ← extract `watch1`, `watch2`, `reload` from `proxy.go`
20. `proxy/proxy.go` ← whatever remains of `proxy.go`

---

## Conventions

- Each package exposes a minimal public API; implementation details remain unexported.
- Unit tests live in the same package (`_test.go`), integration tests in `tests/`.
- Configuration types (`ConfProxy`, `ConfRule`, etc.) stay in `config/` and are referenced by other packages — avoid duplication.
- `global.go` (constants, `Options`) stays at the root until the CLI migration is clarified, then moves to `cmd/`.
