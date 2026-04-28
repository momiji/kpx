package cert_test

import (
	"sync"
	"testing"

	"github.com/momiji/kpx/cert"
)

// Note: Manager.newCertificate always generates 2048-bit RSA keys internally,
// so tests that trigger on-demand cert generation are intentionally slower.

func newManager(t *testing.T, names []string) *cert.Manager {
	t.Helper()
	m, err := cert.NewManager(getCA(t), "test:", names)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// ── Exact name match ──────────────────────────────────────────────────────────

func TestGetCertificate_ExactMatch(t *testing.T) {
	m := newManager(t, []string{"example.com"})
	c, err := m.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected cert for exact name, got nil")
	}
}

func TestGetCertificate_ExactMatchNotFound(t *testing.T) {
	m := newManager(t, []string{"example.com"})
	c, err := m.GetCertificate("other.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("expected nil for unregistered name")
	}
}

// ── Single wildcard *.y.z ─────────────────────────────────────────────────────

func TestGetCertificate_SingleWildcard_Matches(t *testing.T) {
	m := newManager(t, []string{"*.example.com"})
	c, err := m.GetCertificate("sub.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("*.example.com should match sub.example.com")
	}
}

func TestGetCertificate_SingleWildcard_DoesNotMatchParent(t *testing.T) {
	m := newManager(t, []string{"*.example.com"})
	c, err := m.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("*.example.com should not match example.com")
	}
}

func TestGetCertificate_SingleWildcard_DoesNotMatchDeep(t *testing.T) {
	m := newManager(t, []string{"*.example.com"})
	c, err := m.GetCertificate("deep.sub.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("*.example.com should not match deep.sub.example.com")
	}
}

// ── Double wildcard ** ────────────────────────────────────────────────────────

func TestGetCertificate_DoubleStar_MatchesAnything(t *testing.T) {
	m := newManager(t, []string{"**"})
	for _, dns := range []string{"a.com", "b.c.d", "single"} {
		c, err := m.GetCertificate(dns)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", dns, err)
		}
		if c == nil {
			t.Fatalf("** should match %q", dns)
		}
	}
}

func TestGetCertificate_DoubleStarDomain_Matches(t *testing.T) {
	m := newManager(t, []string{"**.example.com"})
	c, err := m.GetCertificate("deep.sub.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("**.example.com should match deep.sub.example.com")
	}
}

func TestGetCertificate_DoubleStarDomain_DoesNotMatchOtherDomain(t *testing.T) {
	m := newManager(t, []string{"**.example.com"})
	c, err := m.GetCertificate("sub.other.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("**.example.com should not match sub.other.com")
	}
}

// ── Caching ───────────────────────────────────────────────────────────────────

func TestGetCertificate_CachesExactLookup(t *testing.T) {
	m := newManager(t, []string{"**"})
	c1, err := m.GetCertificate("cached.example.com")
	if err != nil || c1 == nil {
		t.Fatalf("first lookup: cert=%v err=%v", c1, err)
	}
	c2, err := m.GetCertificate("cached.example.com")
	if err != nil || c2 == nil {
		t.Fatalf("second lookup: cert=%v err=%v", c2, err)
	}
	if c1 != c2 {
		t.Error("second lookup should return the same *tls.Certificate pointer (cached)")
	}
}

func TestGetCertificate_WildcardEntrySharedBySubdomains(t *testing.T) {
	// Two subdomains under the same *.example.com wildcard should share the same cert.
	m := newManager(t, []string{"*.example.com"})
	c1, err := m.GetCertificate("a.example.com")
	if err != nil || c1 == nil {
		t.Fatalf("first: %v %v", c1, err)
	}
	c2, err := m.GetCertificate("b.example.com")
	if err != nil || c2 == nil {
		t.Fatalf("second: %v %v", c2, err)
	}
	if c1 != c2 {
		t.Error("both subdomains should share the same pre-generated wildcard cert")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestGetCertificate_Concurrent_SameDNS(t *testing.T) {
	m := newManager(t, []string{"**"})
	const n = 20
	results := make([]*struct{ c interface{}; err error }, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			c, err := m.GetCertificate("concurrent.example.com")
			results[i] = &struct{ c interface{}; err error }{c, err}
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, r.err)
		}
		if r.c == nil {
			t.Errorf("goroutine %d: expected non-nil cert", i)
		}
	}
}

func TestGetCertificate_Concurrent_DifferentDNS(t *testing.T) {
	m := newManager(t, []string{"**"})
	hosts := []string{"alpha.com", "beta.com", "gamma.com", "delta.com", "epsilon.com"}
	var wg sync.WaitGroup
	wg.Add(len(hosts))
	for _, h := range hosts {
		go func(dns string) {
			defer wg.Done()
			c, err := m.GetCertificate(dns)
			if err != nil {
				t.Errorf("%s: unexpected error: %v", dns, err)
			}
			if c == nil {
				t.Errorf("%s: expected non-nil cert", dns)
			}
		}(h)
	}
	wg.Wait()
}

// ── NewManager error propagation ──────────────────────────────────────────────

func TestNewManager_EmptyNames(t *testing.T) {
	m, err := cert.NewManager(getCA(t), "pfx:", nil)
	if err != nil {
		t.Fatalf("NewManager with no names: %v", err)
	}
	c, err := m.GetCertificate("anything.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("expected nil cert with no registered names")
	}
}
