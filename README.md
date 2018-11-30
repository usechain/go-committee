Node for committee, establish node P2P connection, private key sharing,
committee public key upload, read identity authentication request and 
checking

## Building the source

Building go-committee requires both a Go (version 1.7 or later) and a C compiler.
You can install them using your favourite package manager.
Once the dependencies are installed, run

    make usedCommittee

or, to build the full suite of utilities:

    make all


## Running the committee

Update the self-profile
run

    keygenerater

And run

    committee -asym