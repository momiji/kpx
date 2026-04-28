package certs

import (
	"crypto/tls"
	"strings"
	"sync"
	"time"
)

type DefaultCertManager struct {
	lock         sync.RWMutex
	prefix       string
	ca           *Cert
	certificates map[string]*tls.Certificate
	lastMicro    int64
}

func NewDefaultCertManager(ca *Cert, prefix string, names []string) (*DefaultCertManager, error) {
	m := DefaultCertManager{
		prefix:       prefix,
		ca:           ca,
		certificates: make(map[string]*tls.Certificate),
	}
	for _, dns := range names {
		var err error
		switch {
		case strings.HasPrefix(dns, "*."):
			m.certificates[dns], err = m.newCertificate(dns)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(dns, "**."), dns == "**":
			m.certificates[dns] = nil
		default:
			m.certificates[dns], err = m.newCertificate(dns)
			if err != nil {
				return nil, err
			}
		}
	}
	return &m, nil
}

func (m *DefaultCertManager) GetCertificate(dns string) (*tls.Certificate, error) {
	m.lock.RLock()
	cert, err := m.findCertificate(dns, false)
	m.lock.RUnlock()
	if err != nil || cert != nil {
		return cert, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.findCertificate(dns, true)
}

func (m *DefaultCertManager) newCertificate(dns string) (*tls.Certificate, error) {
	newMicro := time.Now().UnixMicro()
	if newMicro <= m.lastMicro {
		newMicro = m.lastMicro + 1
	}
	m.lastMicro = newMicro
	server, err := NewCert(NewBasicHttpsCertConfig(m.prefix+dns, []string{dns}, m.lastMicro), 2048, m.ca)
	if err != nil {
		return nil, err
	}
	pub, priv, err := server.ToPEM()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(pub), []byte(priv))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *DefaultCertManager) findCertificate(dns string, lock bool) (*tls.Certificate, error) {
	// exact match: x.y.z
	if cert, ok := m.certificates[dns]; ok {
		return cert, nil
	}

	split := strings.Split(dns, ".")
	domain := ""

	// wildcard match: *.y.z
	if len(split) > 1 {
		wc := make([]string, len(split))
		copy(wc, split)
		wc[0] = "*"
		domain = strings.Join(wc, ".")
		if cert, ok := m.certificates[domain]; ok {
			if lock {
				m.certificates[dns] = cert
				return cert, nil
			}
			return nil, nil
		}
	}

	// double-wildcard match: **.y.z, **.z, **
	for i := 0; i < len(split); i++ {
		wc := append([]string{"**"}, split[i+1:]...)
		domains := strings.Join(wc, ".")
		if _, ok := m.certificates[domains]; ok {
			if lock {
				name := domain
				if name == "" {
					name = dns
				}
				cert, err := m.newCertificate(name)
				if err != nil {
					return nil, err
				}
				m.certificates[dns] = cert
				if domain != "" {
					m.certificates[domain] = cert
				}
				return cert, nil
			}
			return nil, nil
		}
	}

	return nil, nil
}
