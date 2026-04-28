package kpx

import (
	"fmt"
	"os"

	"github.com/howeyc/gopass"
	"github.com/momiji/kpx/utils"
)

func encryptPassword() {
	fmt.Printf("Encrypt a password - key location is `%s`\n", options.KeyFile)
	fmt.Print("Password: ")
	pwdBytes, err := gopass.GetPasswdMasked()
	if err != nil {
		os.Exit(1)
	}
	fmt.Printf("Encrypted: %s%s\n", ENCRYPTED, utils.Encrypt(string(pwdBytes), options.KeyFile))
	os.Exit(0)
}
