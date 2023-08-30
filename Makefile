kpx: $(wildcard *.go go.mod go.sum)
	go build -o kpx -ldflags="-s -w -X main.Version=dev/$$(date +%FT%T%z)" cli/main.go

.PHONY: mod
mod:
	go mod tidy
	go mod vendor

.PHONY: force
force: clean kpx

.PHONY: run
tests: kpx
	./tests/run.sh

.PHONY: clean
clean:
	rm -f kpx
