package kpx

import "github.com/ccding/go-logging/logging"

// program global settings
var AppVersion = "dev"
var AppUrl = "https://github.com/momiji/kpx"
var AppName = "kpx"
var AppUpdateUrl = "https://api.github.com/repos/momiji/kpx/releases/latest"
var AppDefaultDomain = ".EXAMPLE.COM"
var AppDefaultKrb5 = `
[libdefaults]
dns_lookup_kdc = true
dns_lookup_realm = true
permitted_enctypes = sha1WithRSAEncryption-CmsOID rc2CBC-EnvOID rsaEncryption-EnvOID rsaES-OAEP-ENV-OID aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha384-192 camellia256-cts-cmac aes256-cts-hmac-sha1-96
# force TCP instead of UDP, timeout for KDC with a small value and max retries per kdc to 1
udp_preference_limit = 1
max_retries = 1
kdc_timeout = 3000
`

// program global options
var options Options
var debug bool
var trace bool
var logger *logging.Logger
var noAuth = ""

// timeout in seconds for dialing to peer
const DEFAULT_CONNECT_TIMEOUT = 10

// timeout in seconds for read/write operations, before automatically closing connections
const DEFAULT_IDLE_TIMOUT = 0

// timeout in seconds for closing infinite pipes once one peer has closed it's connection
const DEFAULT_CLOSE_TIMEOUT = 10

// timeout in seconds for a connection to stay in pool before closing
const POOL_CLOSE_TIMEOUT = 30
const POOL_CLOSE_TIMEOUT_ADD = 5

// config automatic reloading
const RELOAD_TEST_TIMEOUT = 10
const RELOAD_FORCE_TIMEOUT = 60 * 60
const KDC_TEST_TIMEOUT = 10

// max header size, to buffer request headers
const HEADER_MAX_SIZE = 32 * 1024

// encrypted password
const ENCRYPTED = "encrypted:"

type Options struct {
	ShowHelp    bool
	ShowVersion bool
	User        string
	Timeout     int
	Encrypt     bool
	Config      string
	KeyFile     string
	Listen      string
	Proxy       string
	Debug       bool
	Trace       bool
	Verbose     bool
	ACL         []string

	bindHost  string
	bindPort  int
	proxyHost string
	proxyPort int
	login     string
	domain    string
}
