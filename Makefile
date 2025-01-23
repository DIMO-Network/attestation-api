.PHONY: clean run build install dep test lint format docker

SHELL := /bin/bash
PATHINSTBIN = $(abspath ./bin)
export PATH := $(PATHINSTBIN):$(PATH)

BIN_NAME					?= attestation-api
DEFAULT_INSTALL_DIR			:= $(go env GOPATH)/$(PATHINSTBIN)
DEFAULT_ARCH				:= $(shell go env GOARCH)
DEFAULT_GOOS				:= $(shell go env GOOS)
ARCH						?= $(DEFAULT_ARCH)
GOOS						?= $(DEFAULT_GOOS)
INSTALL_DIR					?= $(DEFAULT_INSTALL_DIR)
.DEFAULT_GOAL 				:= run


VERSION   := $(shell git describe --tags || echo "v0.0.0")
VER_CUT   := $(shell echo $(VERSION) | cut -c2-)

# Dependency versions
GOLANGCI_VERSION   = latest
SWAGGO_VERSION     = $(shell go list -m -f '{{.Version}}' github.com/swaggo/swag)
MOCKGEN_VERSION    = $(shell go list -m -f '{{.Version}}' go.uber.org/mock)
PROTOC_VERSION             = 28.3
PROTOC_GEN_GO_VERSION      = $(shell go list -m -f '{{.Version}}' google.golang.org/protobuf)
PROTOC_GEN_GO_GRPC_VERSION = v1.5.1

help:
	@echo "\nSpecify a subcommand:\n"
	@grep -hE '^[0-9a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;36m%-20s\033[m %s\n", $$1, $$2}'
	@echo ""

build:
	@CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(ARCH) \
		go build -o $(PATHINSTBIN)/$(BIN_NAME) ./cmd/$(BIN_NAME)

run: build
	@./$(PATHINSTBIN)/$(BIN_NAME)
all: clean target

clean:
	@rm -rf $(PATHINSTBIN)
	
install: build
	@install -d $(INSTALL_DIR)
	@rm -f $(INSTALL_DIR)/$(BIN_NAME)
	@cp $(PATHINSTBIN)/$(BIN_NAME) $(INSTALL_DIR)/$(BIN_NAME)

tidy: 
	@go mod tidy

test: ## run tests
	@go test ./...

lint: ## run linter
	@golangci-lint run --timeout 10m

docker: dep ## build docker image
	@docker build -f ./Dockerfile . -t dimozone/$(BIN_NAME):$(VER_CUT)
	@docker tag dimozone/$(BIN_NAME):$(VER_CUT) dimozone/$(BIN_NAME):latest

tools-golangci-lint: ## install golangci-lint
	@mkdir -p $(PATHINSTBIN)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | BINARY=golangci-lint bash -s -- ${GOLANGCI_VERSION}

tools-swagger: ## install swagger tool
	@mkdir -p $(PATHINSTBIN)
	GOBIN=$(PATHINSTBIN) go install github.com/swaggo/swag/cmd/swag@$(SWAGGO_VERSION)

tools-mockgen: ## install mockgen tool
	@mkdir -p $(PATHINSTBIN)
	GOBIN=$(PATHINSTBIN) go install go.uber.org/mock/mockgen@$(MOCKGEN_VERSION)

tools-protoc:
	@mkdir -p $(PATHINSTBIN)
	rm -rf $(PATHINSTBIN)/protoc
ifeq ($(shell uname | tr A-Z a-z), darwin)
	curl -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-osx-x86_64.zip > bin/protoc.zip
endif
ifeq ($(shell uname | tr A-Z a-z), linux)
	curl -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip > bin/protoc.zip
endif
	unzip -o $(PATHINSTBIN)/protoc.zip -d $(PATHINSTBIN)/protoclib 
	mv -f $(PATHINSTBIN)/protoclib/bin/protoc $(PATHINSTBIN)/protoc
	rm -rf $(PATHINSTBIN)/include
	mv $(PATHINSTBIN)/protoclib/include $(PATHINSTBIN)/ 
	rm $(PATHINSTBIN)/protoc.zip

tools-protoc-gen-go:
	@mkdir -p $(PATHINSTBIN)
	rm -f $(PATHINSTBIN)/protoc-gen-go
	curl -L https://github.com/protocolbuffers/protobuf-go/releases/download/${PROTOC_GEN_GO_VERSION}/protoc-gen-go.${PROTOC_GEN_GO_VERSION}.$(shell uname | tr A-Z a-z).amd64.tar.gz | tar -zOxf - protoc-gen-go > $(PATHINSTBIN)/protoc-gen-go
	@chmod +x $(PATHINSTBIN)/protoc-gen-go

tools-protoc-gen-go-grpc:
	@mkdir -p $(PATHINSTBIN)
	rm -f $(PATHINSTBIN)/protoc-gen-go-grpc
	curl -L https://github.com/grpc/grpc-go/releases/download/cmd/protoc-gen-go-grpc/${PROTOC_GEN_GO_GRPC_VERSION}/protoc-gen-go-grpc.${PROTOC_GEN_GO_GRPC_VERSION}.$(shell uname | tr A-Z a-z).amd64.tar.gz | tar -zOxf - ./protoc-gen-go-grpc > $(PATHINSTBIN)/protoc-gen-go-grpc
	@chmod +x $(PATHINSTBIN)/protoc-gen-go-grpc


make tools: tools-golangci-lint tools-swagger tools-mockgen tools-protoc tools-protoc-gen-go tools-protoc-gen-go-grpc## install all tools

generate: generate-swagger generate-go generate-grpc ## run all file generation for the project

generate-swagger: ## generate swagger documentation
	@swag -version
	swag init -g cmd/attestation-api/main.go --parseDependency --parseInternal

generate-go:## run go generate
	@go generate ./...

generate-grpc: ## generate grpc files
	@protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/grpc/*.proto