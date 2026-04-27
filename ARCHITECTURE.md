# Architecture modulaire — KPX v2

## Contexte

KPX est un proxy HTTP/SOCKS authentifiant (Kerberos, Basic, SOCKS) avec rechargement de configuration à chaud, support du PAC JavaScript, génération de certificats TLS pour le MITM, et une interface TUI optionnelle.

### Problèmes de la structure actuelle

| Fichier | Lignes | Problème |
|---|---|---|
| `config.go` | ~2500 | Fait tout : parsing, validation, génération PAC, génération certs, matching de règles |
| `process.go` | ~2000 | Fait tout : boucle HTTP, authentification, tunneling CONNECT, serveur local |
| `proxy.go` | ~800 | Mélange : serveur TCP, pool de connexions, rechargement, watchers |
| Tous dans `package kpx` | — | Frontières invisibles, impossible de tester un composant en isolation |

---

## Architecture cible

### Vue d'ensemble

```
kpx/
├── main.go                    # Point d'entrée (< 20 lignes)
├── global.go                  # Constantes globales, Options CLI
│
├── config/                    # Chargement et validation de la configuration
│   ├── config.go              # Types Config, Conf, loaders (YAML/CLI)
│   ├── rule.go                # Matching de règles (matchHttp, matchSocks, HostCache)
│   ├── validate.go            # Validation et construction (check, build)
│   └── pac_gen.go             # Génération du fichier proxy.pac
│
├── proxy/                     # Serveur proxy et cycle de vie
│   ├── proxy.go               # Struct Proxy, start(), stop()
│   ├── reload.go              # Rechargement à chaud (watch1, watch2, reload)
│   └── pool.go                # Pool de connexions upstream (connPool)
│
├── handler/                   # Traitement des requêtes (pipeline)
│   ├── process.go             # Struct Process, boucle principale processHttp()
│   ├── http.go                # Traitement HTTP standard (processChannel)
│   ├── connect.go             # Tunnel CONNECT / HTTPS (processConnect)
│   └── local.go               # Serveur web local (/proxy.pac, /status)
│
├── auth/                      # Authentification upstream
│   ├── auth.go                # Interface Authenticator
│   ├── kerberos.go            # Auth Kerberos (SPNEGO/Negotiate)
│   ├── basic.go               # Auth Basic (base64)
│   └── store.go               # KerberosStore : gestion multi-clients Kerberos
│
├── transport/                 # Couche réseau bas niveau
│   ├── conn.go                # TimedConn, CloseAwareConn
│   └── chunked.go             # chunkedReader (décodage chunked HTTP)
│
├── cert/                      # Gestion des certificats TLS
│   ├── cert.go                # Génération de certificats (RSA, X.509)
│   └── manager.go             # CertsManager : cache et wildcards
│
├── pac/                       # Exécution de fichiers PAC (JavaScript)
│   └── pac.go                 # PacExecutor, pool de runtimes goja
│
├── crypto/                    # Chiffrement des mots de passe
│   └── crypto.go              # AES-GCM, gestion du fichier .key
│
├── log/                       # Logging
│   └── log.go                 # Init, niveaux, masquage des headers sensibles
│
├── util/                      # Utilitaires partagés
│   └── mre.go                 # ManualResetEvent (synchronisation goroutines)
│
├── ui/                        # Interface TUI / console (existant)
│   ├── ui.go
│   ├── ui_data.go
│   ├── ui_tui.go
│   └── ui_tconsole.go
│
└── term/                      # Abstraction terminal (existant)
```

---

## Description des modules

### `config/` — Configuration

**Responsabilité unique** : charger, valider et exposer la configuration.

```go
// config/config.go
package config

type Config struct {
    Conf       *Conf
    PacCache   *pac.PacExecutor    // injecté après build
    CertMgr    *cert.CertsManager  // injecté après build
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

func Load(path string) (*Config, error)       // depuis fichier
func LoadFromOptions(opts *Options) (*Config, error) // depuis CLI
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

**Ce qui sort de config.go actuel** : la génération PAC va dans `config/pac_gen.go`, la génération de certs va dans `cert/`, le matching va dans `config/rule.go`.

---

### `proxy/` — Serveur et cycle de vie

**Responsabilité** : écouter les connexions entrantes, gérer le rechargement de config.

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
    conns map[string]*list.List  // clé: nom du proxy upstream
}

func (cp *ConnPool) Get(proxy string) (net.Conn, bool)
func (cp *ConnPool) Put(proxy string, conn net.Conn)
func (cp *ConnPool) Evict(proxy string)
```

---

### `handler/` — Pipeline de traitement

**Responsabilité** : traiter une connexion cliente de bout en bout.

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

// Traitement d'une requête HTTP simple
func (p *Process) handleRequest(req *request.ProxyRequest) error

// handler/connect.go
// Tunnel CONNECT
func (p *Process) handleConnect(req *request.ProxyRequest) error

// handler/local.go
// Serveur local (/proxy.pac, /status, /reload)
func (p *Process) handleLocal(req *request.ProxyRequest) error
```

---

### `auth/` — Authentification

**Responsabilité** : abstraire les mécanismes d'authentification upstream.

```go
// auth/auth.go
package auth

// Interface commune à tous les mécanismes
type Authenticator interface {
    // Calcule la valeur du header Proxy-Authorization
    Authorize(req *http.Request, challenge string) (string, error)
    // Nom du schéma (Negotiate, Basic, ...)
    Scheme() string
}

func New(proxy *config.ConfProxy, cred *config.ConfCred) (Authenticator, error)
```

```go
// auth/store.go
package auth

// Gère les clients Kerberos (login natif OS ou user/password)
type Store struct {
    mu      sync.Mutex
    clients map[string]*KerberosClient
}

func NewStore() *Store
func (s *Store) GetOrCreate(realm, user, pass string) (*KerberosClient, error)
func (s *Store) LoadNative(conf *config.Config) error
```

---

### `transport/` — Couche réseau

**Responsabilité** : abstractions réseau réutilisables.

```go
// transport/conn.go
package transport

type TimedConn struct { /* net.Conn + timeouts */ }
type CloseAwareConn struct { /* détection fermeture distante */ }

func NewTimed(conn net.Conn, timeout time.Duration) *TimedConn
func NewCloseAware(conn net.Conn) *CloseAwareConn
func Configure(conn net.Conn) error  // TCP_NODELAY
```

---

### `cert/` — Certificats TLS

**Responsabilité** : génération et cache de certificats X.509.

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

### `pac/` — PAC JavaScript

**Responsabilité** : compiler et exécuter des fichiers PAC.

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

### `crypto/` — Chiffrement

**Responsabilité** : chiffrer/déchiffrer les mots de passe de la config.

```go
// crypto/crypto.go
package crypto

func Encrypt(password string) (string, error)
func Decrypt(encoded string) (string, error)
func IsEncrypted(s string) bool
func InteractiveEncrypt() error  // CLI interactif
```

---

### `util/` — Utilitaires

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

## Diagramme de dépendances

```
main.go
  └── proxy/proxy.go
        ├── config/           (chargement + matching)
        │     ├── pac/        (génération proxy.pac)
        │     └── cert/       (génération certificats)
        ├── handler/          (traitement requêtes)
        │     ├── auth/       (authentification upstream)
        │     ├── transport/  (connexions réseau)
        │     ├── config/     (règles, lookup)
        │     └── ui/         (stats trafic)
        ├── auth/store        (sessions Kerberos)
        ├── crypto/           (déchiffrement mots de passe)
        ├── log/              (logging)
        └── util/             (MRE, synchronisation)

ui/     ← aucune dépendance vers kpx (sens unique)
term/   ← aucune dépendance vers kpx (sens unique)
```

**Règle fondamentale** : les dépendances vont toujours vers le bas. `handler` connaît `config` et `auth`, mais `config` ne connaît pas `handler`.

---

## Stratégie de migration

La migration se fait **fichier par fichier**, dans cet ordre de priorité :

### Phase 1 — Fondations (aucun risque)
1. `util/mre.go` ← extraire `mre.go`
2. `transport/conn.go` ← extraire `conn.go`
3. `transport/chunked.go` ← extraire `chunked.go`
4. `crypto/crypto.go` ← extraire `password.go`
5. `log/log.go` ← extraire `log.go`

### Phase 2 — Domaines isolés
6. `pac/pac.go` ← extraire `pac.go`
7. `cert/cert.go` + `cert/manager.go` ← extraire `certs.go` + `certs_manager.go`
8. `auth/kerberos.go` + `auth/store.go` ← extraire `kerberos.go` + `kerberos_store.go`
9. `auth/basic.go` ← extraire la logique Basic de `process.go`

### Phase 3 — Configuration (travail principal)
10. `config/rule.go` ← extraire `matchHttp`, `matchSocks`, `HostCache` de `config.go`
11. `config/validate.go` ← extraire `check()`, `build()` de `config.go`
12. `config/pac_gen.go` ← extraire `genPac()` de `config.go`
13. `config/config.go` ← ce qui reste

### Phase 4 — Handler (travail principal)
14. `handler/local.go` ← extraire `webServer()` de `process.go`
15. `handler/connect.go` ← extraire `processConnect()` de `process.go`
16. `handler/http.go` ← extraire `processChannel()` de `process.go`
17. `handler/process.go` ← ce qui reste de `process.go`

### Phase 5 — Proxy
18. `proxy/pool.go` ← extraire `connPool` de `proxy.go`
19. `proxy/reload.go` ← extraire `watch1`, `watch2`, `reload` de `proxy.go`
20. `proxy/proxy.go` ← ce qui reste de `proxy.go`

---

## Conventions

- Chaque package expose une API publique minimale ; les détails d'implémentation restent non exportés.
- Les tests unitaires se placent dans le même package (`_test.go`), les tests d'intégration dans `tests/`.
- Les types de configuration (`ConfProxy`, `ConfRule`, etc.) restent dans `config/` et sont référencés par les autres packages — éviter la duplication.
- `global.go` (constantes, `Options`) reste à la racine le temps que la migration CLI soit clarifiée, puis migre vers `cmd/`.
