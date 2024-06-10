.PHONY: clean run build install dep test lint format docker
export PATH := $(abspath bin/):${PATH}
BIN_NAME					?= attestation-api
DEFAULT_INSTALL_DIR			:= $(go env GOPATH)/bin
DEFAULT_ARCH				:= $(shell go env GOARCH)
DEFAULT_GOOS				:= $(shell go env GOOS)
ARCH						?= $(DEFAULT_ARCH)
GOOS						?= $(DEFAULT_GOOS)
INSTALL_DIR					?= $(DEFAULT_INSTALL_DIR)
.DEFAULT_GOAL 				:= run


VERSION   := $(shell git describe --tags || echo "v0.0.0")
VER_CUT   := $(shell echo $(VERSION) | cut -c2-)

# Dependency versions
GOLANGCI_VERSION   = v1.56.2


build:
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(ARCH) \
		go build -o bin/$(BIN_NAME) ./cmd/$(BIN_NAME)

run: build
	@./bin/$(BIN_NAME)
all: clean target

clean:
	@rm -rf bin
	
install: build
	@install -d $(INSTALL_DIR)
	@rm -f $(INSTALL_DIR)/$(BIN_NAME)
	@cp bin/$(BIN_NAME) $(INSTALL_DIR)/$(BIN_NAME)

tidy: 
	@go mod tidy

test:
	@go test ./...

lint:
	@golangci-lint run

format:
	@golangci-lint run --fix

docker: dep
	@docker build -f ./Dockerfile . -t dimozone/$(BIN_NAME):$(VER_CUT)
	@docker tag dimozone/$(BIN_NAME):$(VER_CUT) dimozone/$(BIN_NAME):latest

tools-golangci-lint:
	@mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | BINARY=golangci-lint bash -s -- ${GOLANGCI_VERSION}

tools: tools-golangci-lint 