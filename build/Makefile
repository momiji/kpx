krb-proxy: $(wildcard *.go go.mod go.sum)
	go mod tidy
	go build -ldflags="-s -w -X main.Version=1.0.0"

build: krb-proxy

force: clean krb-proxy

.PHONY: run
run: krb-proxy
	./krb-proxy -c tests/ti.yaml

clean:
	rm -f krb-proxy
