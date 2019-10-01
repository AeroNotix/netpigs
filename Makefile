BIN=netpigs
ARTIFACTS ?=./artifacts
CIRCLE_BRANCH ?= dev
CIRCLE_BUILD_NUM ?= $(shell git rev-parse --short HEAD)
GO_BUILD_LD_FLAGS=-ldflags="-s -w"
GO_FILES=$(wildcard **/*.go)

ifeq (,$(wildcard .version))
VERSION=${CIRCLEBRANCH}.${CIRCLE_BUILD_NUM}
else
VERSION=$(shell cat .version)
endif

.PHONY: build test

build:
	go build ${BIN}.go

build-race:
	go build -race ${BIN}.go

test:
	go test -coverprofile=coverage.out ./... && \
	go tool cover -html=coverage.out && \
	staticcheck ./...

define go_build
	@mkdir -p ${ARTIFACTS}
	GOOS=$(1) GOARCH=$(2) go build ${GO_BUILD_LD_FLAGS} -o $(3)_$1_$2 $(4)
	@tar --transform='flags=r;s|$3_$1_$2|$3|' \
		-czf ${ARTIFACTS}/${BIN}_${VERSION}_$1_$2.tar.gz \
		$3_$1_$2 README.md fixtures
	@rm $3_$1_$2
endef

${ARTIFACTS}/${BIN}_${VERSION}_linux_arm64.tar.gz: ${GO_FILES}
	$(call go_build,linux,arm64,${BIN},${BIN}.go)
${ARTIFACTS}/${BIN}_${VERSION}_linux_amd64.tar.gz: ${GO_FILES}
	$(call go_build,linux,amd64,${BIN},${BIN}.go)
${ARTIFACTS}/${BIN}_${VERSION}_darwin_amd64.tar.gz: ${GO_FILES}
	$(call go_build,darwin,amd64,${BIN},${BIN}.go)

crossbuild: ${ARTIFACTS}/${BIN}_${VERSION}_linux_arm64.tar.gz \
			${ARTIFACTS}/${BIN}_${VERSION}_linux_amd64.tar.gz \
			${ARTIFACTS}/${BIN}_${VERSION}_darwin_amd64.tar.gz

validate-circle-conf:
	circleci config validate .circleci/config.yml
