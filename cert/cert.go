package cert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

// See https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

type Cert struct {
	Priv *rsa.PrivateKey
	Pub  *x509.Certificate
}

func NewCert(cert *x509.Certificate, bits int, ca *Cert) (*Cert, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	caPriv := priv
	caPub := cert
	if ca != nil {
		caPriv = ca.Priv
		caPub = ca.Pub
	}

	pubBytes, err := x509.CreateCertificate(rand.Reader, cert, caPub, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParseCertificate(pubBytes)
	if err != nil {
		return nil, err
	}

	return &Cert{
		Priv: priv,
		Pub:  pub,
	}, nil
}

func NewBasicCACertConfig(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(time.Hour * -1),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

func NewBasicHttpsCertConfig(cn string, names []string, serial int64) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cn,
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(time.Hour * -1),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, name)
		}
	}
	return cert
}

func NewCertFromPEM(public, private string) (*Cert, error) {
	block, _ := pem.Decode([]byte(public))
	if block == nil {
		return nil, errors.New("failed to decode public PEM block")
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	block, _ = pem.Decode([]byte(private))
	if block == nil {
		return nil, errors.New("failed to decode private PEM block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Cert{Priv: priv, Pub: pub}, nil
}

func NewCertFromFiles(public, private string) (*Cert, error) {
	pub, err := os.ReadFile(public)
	if err != nil {
		return nil, err
	}
	priv, err := os.ReadFile(private)
	if err != nil {
		return nil, err
	}
	return NewCertFromPEM(string(pub), string(priv))
}

func (c *Cert) ToPEM() (string, string, error) {
	pub := new(bytes.Buffer)
	if err := pem.Encode(pub, &pem.Block{Type: "CERTIFICATE", Bytes: c.Pub.Raw}); err != nil {
		return "", "", err
	}
	priv := new(bytes.Buffer)
	if err := pem.Encode(priv, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.Priv)}); err != nil {
		return "", "", err
	}
	return pub.String(), priv.String(), nil
}

func (c *Cert) SaveToFiles(public, private string) error {
	pub, priv, err := c.ToPEM()
	if err != nil {
		return err
	}
	if err = os.WriteFile(public, []byte(pub), 0644); err != nil {
		return err
	}
	return os.WriteFile(private, []byte(priv), 0600)
}

func NewPbkdfCert(cert *x509.Certificate, bits int, ca *Cert, password []byte, salt []byte, iter int) (*Cert, error) {
	// Derive a 32-byte AES-256 key via PBKDF2, then use AES-CTR as an
	// unlimited deterministic stream so RSA prime search never hits EOF.
	key := pbkdf2.Key(password, salt, iter, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	reader := &randomReader{r: &ctrReader{stream}}
	priv, err := rsa.GenerateKey(reader, bits)
	if err != nil {
		return nil, err
	}

	caPriv := priv
	caPub := cert
	if ca != nil {
		caPriv = ca.Priv
		caPub = ca.Pub
	}

	pubBytes, err := x509.CreateCertificate(rand.Reader, cert, caPub, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParseCertificate(pubBytes)
	if err != nil {
		return nil, err
	}
	return &Cert{Priv: priv, Pub: pub}, nil
}

// randomReader suppresses the randutil.MaybeReadByte single-byte probe used
// internally by rsa.GenerateKey, so that the underlying stream is consumed
// deterministically.
type randomReader struct {
	r io.Reader
}

func (r randomReader) Read(p []byte) (n int, err error) {
	if len(p) == 1 {
		p[0] = 0
		return 1, nil
	}
	return r.r.Read(p)
}

// ctrReader wraps a cipher.Stream and produces an unlimited deterministic
// byte sequence by XOR-ing the keystream over a zero buffer.
type ctrReader struct {
	s cipher.Stream
}

func (r *ctrReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	r.s.XORKeyStream(p, p)
	return len(p), nil
}
