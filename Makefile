kpx: $(wildcard *.go go.mod go.sum)
	go mod tidy
	go mod vendor
	go build -o kpx -ldflags="-s -w" cli/main.go

build: kpx

force: clean kpx

fast:
	go build -o kpx -ldflags="-s -w" cli/main.go

.PHONY: run
run: kpx
	./kpx -c tests/ti.yaml

clean:
	rm -f kpx
