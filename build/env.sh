#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
usedir="$workspace/src/github.com/usechain"
if [ ! -L "$usedir/go-committee" ]; then
    mkdir -p "$usedir"
    cd "$usedir"
    ln -s ../../../../../. go-committee
    cd "$root"
fi

# Set up the environment to use the workspace.
GOBIN="$PWD/build/bin"
GOPATH="$workspace"
export GOBIN
export GOPATH

# Run the command inside the workspace.
cd "$usedir/go-committee"
PWD="$usedir/go-committee"

# Launch the arguments with the configured environment.
exec "$@"
