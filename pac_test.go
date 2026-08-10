package kpx

import (
	"testing"
	"time"
)

// Tests below implement the examples given in the official PAC file
// documentation:
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_(PAC)_file

func TestIsPlainHostName(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"www.mozilla.org", false},
		{"www", true},
	}
	for _, tt := range tests {
		if got := isPlainHostName(tt.host); got != tt.want {
			t.Errorf("isPlainHostName(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestDnsDomainIs(t *testing.T) {
	tests := []struct {
		host, domain string
		want         bool
	}{
		{"www.mozilla.org", ".mozilla.org", true},
		{"www", ".mozilla.org", false},
	}
	for _, tt := range tests {
		if got := dnsDomainIs(tt.host, tt.domain); got != tt.want {
			t.Errorf("dnsDomainIs(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
		}
	}
}

func TestLocalHostOrDomainIs(t *testing.T) {
	tests := []struct {
		host, hostdom string
		want          bool
	}{
		{"www.mozilla.org", "www.mozilla.org", true},
		{"www", "www.mozilla.org", true},
		{"www.mozilla.org", "www.mozilla.com", false},
		{"home.mozilla.org", "www.mozilla.org", false},
	}
	for _, tt := range tests {
		if got := localHostOrDomainIs(tt.host, tt.hostdom); got != tt.want {
			t.Errorf("localHostOrDomainIs(%q, %q) = %v, want %v", tt.host, tt.hostdom, got, tt.want)
		}
	}
}

func TestIsResolvable(t *testing.T) {
	if !isResolvable("localhost") {
		t.Errorf("isResolvable(%q) = false, want true", "localhost")
	}
	if isResolvable("this-domain-should-not-exist-abcxyz123.invalid") {
		t.Errorf("isResolvable(%q) = true, want false", "this-domain-should-not-exist-abcxyz123.invalid")
	}
}

func TestIsInNet(t *testing.T) {
	tests := []struct {
		host, pattern, mask string
		want                bool
	}{
		{"127.0.0.1", "127.0.0.0", "255.255.255.0", true},
		{"127.0.0.1", "10.0.0.0", "255.0.0.0", false},
		{"this-domain-should-not-exist-abcxyz123.invalid", "127.0.0.0", "255.0.0.0", false},
	}
	for _, tt := range tests {
		if got := isInNet(tt.host, tt.pattern, tt.mask); got != tt.want {
			t.Errorf("isInNet(%q, %q, %q) = %v, want %v", tt.host, tt.pattern, tt.mask, got, tt.want)
		}
	}
}

func TestDnsResolve(t *testing.T) {
	if got := dnsResolve("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("dnsResolve(%q) = %q, want %q", "127.0.0.1", got, "127.0.0.1")
	}
	if got := dnsResolve("this-domain-should-not-exist-abcxyz123.invalid"); got != "" {
		t.Errorf("dnsResolve(%q) = %q, want %q", "this-domain-should-not-exist-abcxyz123.invalid", got, "")
	}
}

func TestConvertAddr(t *testing.T) {
	tests := []struct {
		ip   string
		want int64
	}{
		{"127.0.0.1", 0x7F000001},
		{"192.168.10.1", 0xC0A80A01},
		{"not-an-ip", 0},
	}
	for _, tt := range tests {
		if got := convert_addr(tt.ip); got != tt.want {
			t.Errorf("convert_addr(%q) = %d, want %d", tt.ip, got, tt.want)
		}
	}
}

func TestMyIpAddress(t *testing.T) {
	ip := myIpAddress()
	if ip == "" {
		t.Fatalf("myIpAddress() returned empty string")
	}
	if convert_addr(ip) == 0 {
		t.Errorf("myIpAddress() = %q, want a valid IPv4 address", ip)
	}
}

func TestDnsDomainLevels(t *testing.T) {
	tests := []struct {
		host string
		want int
	}{
		{"www", 0},
		{"www.netscape.com", 2},
	}
	for _, tt := range tests {
		if got := dnsDomainLevels(tt.host); got != tt.want {
			t.Errorf("dnsDomainLevels(%q) = %d, want %d", tt.host, got, tt.want)
		}
	}
}

func TestShExpMatch(t *testing.T) {
	tests := []struct {
		str, shexp string
		want       bool
	}{
		{"http://home.netscape.com/people/ari/index.html", "*/ari/*", true},
		{"http://home.netscape.com/people/montulli/index.html", "*/ari/*", false},
		{"test1", "test?", true},
		{"test12", "test?", false},
	}
	for _, tt := range tests {
		if got := shExpMatch(tt.str, tt.shexp); got != tt.want {
			t.Errorf("shExpMatch(%q, %q) = %v, want %v", tt.str, tt.shexp, got, tt.want)
		}
	}
}

func TestWeekdayRange(t *testing.T) {
	now := time.Now()
	todayIdx := int(now.Weekday())
	yesterdayIdx := (todayIdx + 6) % 7
	todayCode := days[todayIdx]
	yesterdayCode := days[yesterdayIdx]

	tests := []struct {
		name           string
		start, end, tz string
		want           bool
	}{
		{"whole week always matches", "SUN", "SAT", "GMT", true},
		{"today matches itself", todayCode, todayCode, "", true},
		{"yesterday alone does not match today", yesterdayCode, yesterdayCode, "", false},
		{"unknown day codes never match", "FOO", "BAR", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := weekdayRange(tt.start, tt.end, tt.tz); got != tt.want {
				t.Errorf("weekdayRange(%q, %q, %q) = %v, want %v", tt.start, tt.end, tt.tz, got, tt.want)
			}
		})
	}
}

func TestDateRange(t *testing.T) {
	// dateRange() is not implemented yet (see TODO in pac.go) and always
	// returns true regardless of arguments.
	if got := dateRange(); got != true {
		t.Errorf("dateRange() = %v, want %v", got, true)
	}
}

func TestTimeRange(t *testing.T) {
	// timeRange() is not implemented yet (see TODO in pac.go) and always
	// returns true regardless of arguments.
	if got := timeRange(); got != true {
		t.Errorf("timeRange() = %v, want %v", got, true)
	}
}

func TestAlert(t *testing.T) {
	logInit()
	defer logDestroy()
	// alert() only forwards the message to the logger; it must not panic.
	alert("this is a PAC alert() test message")
}

// TestPacExecutor exercises PacExecutor.NewPac/Run using PAC scripts built
// from the documented helper functions, similar to the sample scripts shown
// on the MDN documentation page.
func TestPacExecutor(t *testing.T) {
	pacJs := `
function FindProxyForURL(url, host) {
    if (isPlainHostName(host))
        return "DIRECT";
    else if (shExpMatch(host, "*.mozilla.org"))
        return "PROXY proxy.mozilla.org:8080";
    else
        return "DIRECT";
}
`
	executor, err := NewPac(pacJs)
	if err != nil {
		t.Fatalf("NewPac() error: %v", err)
	}

	tests := []struct {
		url, host string
		want      string
	}{
		{"http://mail/", "mail", "DIRECT"},
		{"http://www.mozilla.org/", "www.mozilla.org", "PROXY proxy.mozilla.org:8080"},
		{"http://www.example.com/", "www.example.com", "DIRECT"},
	}
	for _, tt := range tests {
		got, err := executor.Run(tt.url, tt.host)
		if err != nil {
			t.Fatalf("Run(%q, %q) error: %v", tt.url, tt.host, err)
		}
		if got != tt.want {
			t.Errorf("Run(%q, %q) = %q, want %q", tt.url, tt.host, got, tt.want)
		}
	}
}

func TestPacExecutorInvalidScript(t *testing.T) {
	if _, err := NewPac("this is not valid javascript {{{"); err == nil {
		t.Fatalf("NewPac() expected error for invalid script, got nil")
	}
}
