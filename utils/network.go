package utils

import "strings"

func SplitHostPort(hostPort, defaultHost, defaultPort string, portFirst bool) (string, string) {
	hp := strings.SplitN(hostPort, ":", 2)
	var host, port string
	if len(hp) == 1 {
		if portFirst {
			host = ""
			port = hp[0]
		} else {
			host = hp[0]
			port = ""
		}
	} else if len(hp) == 2 {
		host = hp[0]
		port = hp[1]
	}
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		host = defaultHost
	}
	if port == "" {
		port = defaultPort
	}
	return host, port
}

func SplitUsername(username, realm string) (string, string) {
	if strings.Contains(username, `\`) {
		p := strings.LastIndex(username, `\`)
		realm = username[:p]
		username = username[p+1:]
	} else if strings.Contains(username, "@") {
		p := strings.LastIndex(username, "@")
		realm = username[p+1:]
		username = username[:p]
	}
	realm = strings.ToUpper(realm)
	return username, realm
}
