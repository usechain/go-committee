# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: committee all clean

GOBIN = $(shell pwd)/build/bin
GO ?= latest

usedCommittee:
	build/env.sh go install ./cmd/committee
	@echo "Done building."
	@echo "Run \"$(GOBIN)/committee\" to launch committee."

all:
	build/env.sh go install ./cmd/*
	@build/init.sh
	@echo "Done building."

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*
