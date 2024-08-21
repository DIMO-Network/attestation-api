.PHONY: clean run build install dep test lint format docker

PATHINSTBIN = $(abspath ./bin)
export PATH := $(PATHINSTBIN):$(PATH)
SHELL := env PATH=$(PATH) $(SHELL)

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
GOLANGCI_VERSION   = v1.56.2
SWAGGO_VERSION     = $(shell go list -m -f '{{.Version}}' github.com/swaggo/swag)
MOCKGEN_VERSION    = $(shell go list -m -f '{{.Version}}' go.uber.org/mock)
PROTOC_VERSION             = 21.12
PROTOC_GEN_GO_VERSION      = 1.30.0
PROTOC_GEN_GO_GRPC_VERSION = 1.3.0

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
	@golangci-lint run

format:
	@golangci-lint run --fix

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
	@mkdir -p bin/protoc
ifeq ($(shell uname | tr A-Z a-z), darwin)
	curl -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-osx-x86_64.zip > bin/protoc.zip
endif
ifeq ($(shell uname | tr A-Z a-z), linux)
	curl -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip > bin/protoc.zip
endif
	unzip bin/protoc.zip -d bin/protoc
	rm bin/protoc.zip

tools-protoc-gen-go:
	@mkdir -p bin
	curl -L https://github.com/protocolbuffers/protobuf-go/releases/download/v${PROTOC_GEN_GO_VERSION}/protoc-gen-go.v${PROTOC_GEN_GO_VERSION}.$(shell uname | tr A-Z a-z).amd64.tar.gz | tar -zOxf - protoc-gen-go > ./bin/protoc-gen-go
	@chmod +x ./bin/protoc-gen-go

tools-protoc-gen-go-grpc:
	@mkdir -p bin
	curl -L https://github.com/grpc/grpc-go/releases/download/cmd/protoc-gen-go-grpc/v${PROTOC_GEN_GO_GRPC_VERSION}/protoc-gen-go-grpc.v${PROTOC_GEN_GO_GRPC_VERSION}.$(shell uname | tr A-Z a-z).amd64.tar.gz | tar -zOxf - ./protoc-gen-go-grpc > ./bin/protoc-gen-go-grpc
	@chmod +x ./bin/protoc-gen-go-grpc
make tools: tools-golangci-lint tools-swagger tools-mockgen tools-protoc tools-protoc-gen-go tools-protoc-gen-go-grpc## install all tools

generate: swagger go-generate ## run all file generation for the project
swagger: ## generate swagger documentation
	@swag -version
	swag init -g cmd/attestation-api/main.go --parseDependency --parseInternal

go-generate:## run go generate
	@go generate ./...

grpc:
	@protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/grpc/*.proto