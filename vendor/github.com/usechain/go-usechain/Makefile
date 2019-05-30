# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: used android ios used-cross swarm evm all test clean
.PHONY: used-linux used-linux-386 used-linux-amd64 used-linux-mips64 used-linux-mips64le
.PHONY: used-linux-arm used-linux-arm-5 used-linux-arm-6 used-linux-arm-7 used-linux-arm64
.PHONY: used-darwin used-darwin-386 used-darwin-amd64
.PHONY: used-windows used-windows-386 used-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest

used:
	build/env.sh go run build/ci.go install ./cmd/used
	@echo "Done building."
	@echo "Run \"$(GOBIN)/used\" to launch used."

all:
	build/env.sh go run build/ci.go install
	@build/usechain.sh

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/used.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/used.framework\" to use the library."

test: all
# build/env.sh go run build/ci.go test
	build/env.sh go test -v ./crypto
	build/env.sh go test -v ./accounts/keystore
# build/env.sh go test -v ./accounts/ca

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

used-cross: used-linux used-darwin used-windows used-android used-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/used-*

used-linux: used-linux-386 used-linux-amd64 used-linux-arm used-linux-mips64 used-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-*

used-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/used
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep 386

used-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/used
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep amd64

used-linux-arm: used-linux-arm-5 used-linux-arm-6 used-linux-arm-7 used-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep arm

used-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/used
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep arm-5

used-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/used
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep arm-6

used-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/used
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep arm-7

used-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/used
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep arm64

used-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/used
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep mips

used-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/used
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep mipsle

used-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/used
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep mips64

used-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/used
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/used-linux-* | grep mips64le

used-darwin: used-darwin-386 used-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/used-darwin-*

used-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/used
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/used-darwin-* | grep 386

used-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/used
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/used-darwin-* | grep amd64

used-windows: used-windows-386 used-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/used-windows-*

used-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/used
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/used-windows-* | grep 386

used-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/used
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/used-windows-* | grep amd64
