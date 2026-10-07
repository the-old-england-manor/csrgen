# Variables
NAME    := csrgen
VERSION ?= latest
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)


##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run the tests
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

##@ Build
bin:
	@mkdir -p bin

.PHONY: build
build: bin ## Build the application for the native architecture
	CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -v -ldflags="-s -w" -o bin/${NAME}-${GOOS}-${GOARCH}-${VERSION} .

.PHONY: build-amd64-linux
build-amd64-linux: GOOS   := linux
build-amd64-linux: GOARCH := amd64
build-amd64-linux: bin ## Build the application for linux-amd64 architecture
	CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -v -ldflags="-s -w" -o bin/${NAME}-${GOOS}-${GOARCH}-${VERSION} .

.PHONY: build-amd64-windows
build-amd64-windows: GOOS   := windows
build-amd64-windows: GOARCH := amd64
build-amd64-windows: bin ## Build the application for windows-amd64 architecture
	CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -v -ldflags="-s -w" -o bin/${NAME}-${GOOS}-${GOARCH}-${VERSION}.exe .

.PHONY: build-amd64-darwin
build-amd64-darwin: GOOS   := darwin
build-amd64-darwin: GOARCH := amd64
build-amd64-darwin: bin ## Build the application for darwin-amd64 architecture
	CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -v -ldflags="-s -w" -o bin/${NAME}-${GOOS}-${GOARCH}-${VERSION} .

.PHONY: build-arm64-darwin
build-arm64-darwin: GOOS   := darwin
build-arm64-darwin: GOARCH := arm64
build-arm64-darwin: bin ## Build the application for darwin-arm64 architecture
	CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -v -ldflags="-s -w" -o bin/${NAME}-${GOOS}-${GOARCH}-${VERSION} .

.PHONY: build-all
build-all: build-amd64-linux build-amd64-windows build-amd64-darwin build-arm64-darwin ## Build the application for all architectures

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf ./bin
