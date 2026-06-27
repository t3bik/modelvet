.PHONY: build test vet lint security fuzz clean

build:
	go build ./...

test:
	go test ./... -race -cover

vet:
	go vet ./...

lint:
	golangci-lint run

security:
	gosec -quiet ./...
	govulncheck ./...

fuzz:
	go test ./internal/gguf/...        -fuzz=FuzzScanGGUF        -fuzztime=30s
	go test ./internal/safetensors/... -fuzz=FuzzScanSafetensors  -fuzztime=30s
	go test ./internal/pickle/...      -fuzz=FuzzScanPickle       -fuzztime=30s

clean:
	go clean ./...
	rm -f modelvet
