//go:build !windows && !linux

package auth

import (
	"errors"

	"github.com/momiji/kpx/log"
)

type NoKerberos struct{}

func NewDefaultNativeKerberos(_ log.Logger) *NoKerberos {
	return &NoKerberos{}
}

func (k *NoKerberos) SafeTryLogin() error {
	return errors.New("unable to use native kerberos on this OS")
}

func (k *NoKerberos) SafeGetToken(protocol string, host string) (*string, error) {
	return nil, errors.New("unable to use native kerberos on this OS")
}
