package certs

import (
	"crypto/tls"
)

type CertManager interface {
	GetCertificate(dns string) (*tls.Certificate, error)
}
