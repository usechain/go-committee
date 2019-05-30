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
	"path/filepath"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/node"
)

var CommitteePasswd = make(chan string, 1)

func DefaultKeystore(argMoonet bool) (ks *keystore.KeyStore){
	// Create an encrypted keystore with standard crypto parameters
	if argMoonet {
		ks = keystore.NewKeyStore(filepath.Join(node.DefaultDataDir(), "moonet/keystore"), keystore.StandardScryptN, keystore.StandardScryptP)
	} else{
		ks = keystore.NewKeyStore(filepath.Join(node.DefaultDataDir(), "keystore"), keystore.StandardScryptN, keystore.StandardScryptP)
	}
	return ks
}

func NewAccount(ks *keystore.KeyStore, passwd string) accounts.Account {
	// Create a new account with the specified encryption passphrase
	newAcc, err := ks.NewAccount(passwd)
	if err != nil {
		fmt.Println("create account failed", err)
	}
	return newAcc
}

func CommitteeAccount(addr common.Address, ks *keystore.KeyStore) (accounts.Account, error) {
	account := accounts.Account{Address: addr}
	wallet, err := ks.Find(account)
	if err != nil {
		log.Error("To be a committee of usechain, need local account","err", err)
		return accounts.Account{}, err
	}
	return wallet, nil
}

