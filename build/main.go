package main

import (
	"github.com/momiji/kpx"
)

var Version = "dev"

func main() {
	kpx.AppName = "krb-proxy"
	kpx.AppDefaultDomain = ".DOMAIN.COM"
	kpx.AppUpdateUrl = ""
	kpx.AppUrl = "https://github.com/momiji/kpx/build"
	kpx.AppVersion = Version
	kpx.Main()
}
