package utils

import (
	"path/filepath"
	"github.com/usechain/go-usechain/node"
)

// DefaultDataDir is the default data directory to use for the databases and other
// persistence requirements.
func DefaultDataDir() string {
	return filepath.Join(node.DefaultDataDir(), "committee") + "/"
}

func DefaultCommDataDir() string {
	return node.DefaultDataDir() + "/"
}
