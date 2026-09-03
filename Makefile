GO ?= go
PROTOC ?= protoc
PROTOC_GEN_GO_VERSION ?= v1.36.12
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2
MODULE := github.com/smshagor-dev/ZeroTrust-FL-Sim
PROTO := proto/fl_service.proto

.PHONY: tools proto certs fmt vet test build run clean

tools:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto:
	$(PROTOC) \
		--go_out=. --go_opt=module=$(MODULE) \
		--go-grpc_out=. --go-grpc_opt=module=$(MODULE) \
		$(PROTO)

certs:
	$(GO) run ./security -out certs/dev

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test: proto
	$(GO) test ./... -count=1

build: proto
	$(GO) build ./cmd/coordinator

run: proto
	$(GO) run ./cmd/coordinator

clean:
	rm -rf certs/dev
