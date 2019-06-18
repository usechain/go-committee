// Copyright 2018 The go-committee Authors
// This file is part of the go-committee library.
//
// The go-committee library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-committee library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-committee library. If not, see <http://www.gnu.org/licenses/>.

package account

import (
	"fmt"
	"os"
	"io/ioutil"
	"math/big"
	"time"
	"testing"
	"path/filepath"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
)

func TestAccountManager(t *testing.T) {
	// Create a temporary folder to work with
	workdir, err := ioutil.TempDir("", "")
	fmt.Println(workdir)
	if err != nil {
		t.Fatalf("Failed to create temporary work dir: %v", err)
	}
	defer os.RemoveAll(workdir)

	// Create an encrypted keystore with standard crypto parameters
	ks := keystore.NewKeyStore(filepath.Join(workdir, "keystore"), keystore.StandardScryptN, keystore.StandardScryptP)

	// Create a new account with the specified encryption passphrase
	newAcc, err := ks.NewAccount("Creation password")
	if err != nil {
		t.Fatalf("Failed to create new account: %v", err)
	}
	// Export the newly created account with a different passphrase. The returned
	// data from this method invocation is a JSON encoded, encrypted key-file
	jsonAcc, err := ks.Export(newAcc, "Creation password", "Export password")
	if err != nil {
		t.Fatalf("Failed to export account: %v", err)
	}

	// Update the passphrase on the account created above inside the local keystore
	if err := ks.Update(newAcc, "Creation password", "Update password"); err != nil {
		t.Fatalf("Failed to update account: %v", err)
	}
	// Delete the account updated above from the local keystore
	if err := ks.Delete(newAcc, "Update password"); err != nil {
		t.Fatalf("Failed to delete account: %v", err)
	}
	// Import back the account we've exported (and then deleted) above with yet
	// again a fresh passphrase
	if _, err := ks.Import(jsonAcc, "Export password", "Import password"); err != nil {
		t.Fatalf("Failed to import account: %v", err)
	}
	// Create a new account to sign transactions with
	signer, err := ks.NewAccount("Signer password")
	if err != nil {
		t.Fatalf("Failed to create signer account: %v", err)
	}
	tx, chain := new(types.Transaction), big.NewInt(1)

	// Sign a transaction with a single authorization
	if _, err := ks.SignTxWithPassphrase(signer, "Signer password", tx, chain); err != nil {
		t.Fatalf("Failed to sign with passphrase: %v", err)
	}
	// Sign a transaction with multiple manually cancelled authorizations
	if err := ks.Unlock(signer, "Signer password"); err != nil {
		t.Fatalf("Failed to unlock account: %v", err)
	}
	if _, err := ks.SignTx(signer, tx, chain); err != nil {
		t.Fatalf("Failed to sign with unlocked account: %v", err)
	}
	if err := ks.Lock(signer.Address); err != nil {
		t.Fatalf("Failed to lock account: %v", err)
	}
	// Sign a transaction with multiple automatically cancelled authorizations
	if err := ks.TimedUnlock(signer, "Signer password", time.Second); err != nil {
		t.Fatalf("Failed to time unlock account: %v", err)
	}
	if _, err := ks.SignTx(signer, tx, chain); err != nil {
		t.Fatalf("Failed to sign with time unlocked account: %v", err)
	}
}

func TestCommitteeAccount(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlTrace, log.StreamHandler(os.Stdout, log.TerminalFormat(true))))

	addr := "0x36B3c80a4FAD8aBd2d9b0d274Ba3564634380515"
	ks := DefaultKeystore(false)
	_, err := CommitteeAccount(common.HexToAddress(addr), ks)
	if err != nil {
		fmt.Println("Not found", err)
	}
}