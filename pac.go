package kpx

import (
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/palantir/stacktrace"
)

type PacExecutor struct {
	js      string
	program *goja.Program
	pool    *sync.Pool
}

func NewPac(pacJs string) (*PacExecutor, error) {
	js := `
(function(url,host) {
%s
return FindProxyForURL(url,host);
})(url,host)
`
	js = fmt.Sprintf(js, pacJs)
	program, err := goja.Compile("", js, false)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to compile regex")
	}
	return &PacExecutor{
		js:      js,
		program: program,
		pool:    &sync.Pool{},
	}, nil
}

func (p *PacExecutor) Run(url, host string) (string, error) {
	// get runtime from pool or create a new one
	var runtime *goja.Runtime
	item := p.pool.Get()
	if item == nil {
		runtime = p.build()
	} else {
		runtime = item.(*goja.Runtime)
	}
	defer p.pool.Put(runtime)
	// execute code
	runtime.Set("url", url)
	runtime.Set("host", host)
	val, err := runtime.RunProgram(p.program)
	if err != nil {
		return "", err // no wrap
	}
	return val.String(), nil
}

func (p *PacExecutor) build() *goja.Runtime {
	runtime := goja.New()
	runtime.Set("isPlainHostName", isPlainHostName)
	runtime.Set("dnsDomainIs", dnsDomainIs)
	runtime.Set("localHostOrDomainIs", localHostOrDomainIs)
	runtime.Set("isResolvable", isResolvable)
	runtime.Set("isInNet", isInNet)
	runtime.Set("dnsResolve", dnsResolve)
	runtime.Set("convert_addr", convert_addr)
	runtime.Set("myIpAddress", myIpAddress)
	runtime.Set("dnsDomainLevels", dnsDomainLevels)
	runtime.Set("shExpMatch", shExpMatch)
	runtime.Set("weekdayRange", weekdayRange)
	runtime.Set("dateRange", dateRange)
	runtime.Set("timeRange", timeRange)
	runtime.Set("alert", alert)
	return runtime
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_(PAC)_file#isPlainHostName

func isPlainHostName(host string) bool {
	return !strings.Contains(host, ".")
}
func dnsDomainIs(host, domain string) bool {
	return strings.HasPrefix(domain, ".") && strings.HasSuffix(host, domain)
}
func localHostOrDomainIs(host, hostdom string) bool {
	return host == hostdom || (!strings.Contains(host, ".") && strings.HasPrefix(hostdom, host))
}
func isResolvable(host string) bool {
	_, err := net.LookupHost(host)
	return err == nil
}
func isInNet(host, pattern, mask string) bool {
	host = dnsResolve(host)
	hostInt := convert_addr(host)
	patternInt := convert_addr(pattern)
	maskInt := convert_addr(mask)
	return hostInt&maskInt == patternInt
}
func dnsResolve(host string) string {
	ips, err := net.LookupHost(host)
	if err != nil {
		return ""
	}
	if len(ips) == 0 {
		return ""
	}
	return ips[0]
}
func convert_addr(ipaddr string) int64 {
	ip := net.ParseIP(ipaddr)
	ipInt := big.NewInt(0)
	ipInt.SetBytes(ip.To4())
	return ipInt.Int64()
}
func myIpAddress() string {
	ips, err := net.LookupHost("localhost")
	if err != nil {
		return "127.0.0.1"
	}
	if len(ips) == 0 {
		return "127.0.0.1"
	}
	return ips[0]
}
func dnsDomainLevels(host string) int {
	return len(strings.Split(host, ".")) - 1
}
func shExpMatch(str, shexp string) bool {
	shexp = strings.ReplaceAll(shexp, ".", `\.`)
	shexp = strings.ReplaceAll(shexp, "*", ".*")
	shexp = strings.ReplaceAll(shexp, "?", ".")
	shexp = "^" + shexp + "$"
	regex, _ := regexp.Compile(shexp)
	return regex.MatchString(str)
}

var days = [...]string{"SUN", "MON", "TUE", "WEN", "THU", "FRI", "SAT"}

func weekdayRange(start, end, tz string) bool {
	startDay := -1
	endDay := -1
	for i, day := range days {
		if start == day {
			startDay = i
		}
		if end == day {
			endDay = i
		}
	}
	if end == "GMT" {
		tz = "GMT"
		endDay = startDay
	}
	today := time.Now()
	if tz == "GMT" {
		today = today.UTC()
	}
	weekDay := int(today.Weekday())
	if startDay <= weekDay && weekDay <= endDay {
		return true
	}
	weekDay += 7
	if startDay <= weekDay && weekDay <= endDay {
		return true
	}
	return false
}
func dateRange() bool {
	// TODO implement PAC dateRange()
	return true
}
func timeRange() bool {
	// TODO implement PAC timeRange()
	return true
}
func alert(message string) {
	logInfo("%s", message)
}
