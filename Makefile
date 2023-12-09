BIN=netpigs
GO_BUILD_LD_FLAGS=-ldflags="-s -w"
GO_FILES=$(wildcard **/*.go)

.PHONY: build test generate

build: generate
	go build ${BIN}.go

generate:
	go generate ./...

build-race: generate
	go build -race ${BIN}.go

test:
	go test -coverprofile=coverage.out ./... && \
	go tool cover -html=coverage.out && \
	staticcheck ./...
