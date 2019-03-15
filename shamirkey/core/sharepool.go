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

package core

import (
	"fmt"
	"crypto/rand"
	"sync"
	//"encoding/hex"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/ecies"
	"github.com/go-wanchain/common/hexutil"
)

const chanSizeLimit = 10

type SharePool struct {
	shareSet 		 map[string][]string
	encryptedSet	 map[string]string

	pendingSet		 map[string]common.Hash
	verifiedSet		 map[string]common.Hash
	VerifiedChan	 chan string
	mu 				 sync.Mutex
}

func NewSharePool() *SharePool{
	return &SharePool{
		shareSet: make(map[string][]string),
		encryptedSet: make(map[string]string),
		pendingSet: make(map[string]common.Hash),
		verifiedSet: make(map[string]common.Hash),
		VerifiedChan:make(chan string, chanSizeLimit),
	}
}

func (self *SharePool)GetVerifiedCertHash(key string) common.Hash {
	return self.verifiedSet[key]
}

func (self *SharePool)SaveAccountSharedCache(A string, bsA string, id int) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.shareSet[A] = append(self.shareSet[A], bsA)
	fmt.Println("SaveAccountSharedCache:::::::::::::::",A, self.shareSet[A])
}

func (self *SharePool)SaveEncryptedData(A string, h common.Hash, data string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.encryptedSet[A] = data
	self.pendingSet[A] = h
}

func (self *SharePool) CheckSharedMsg(usechain *config.Usechain, requires int) {
	self.mu.Lock()
	defer self.mu.Unlock()
	for A, shares := range self.shareSet {
		//check whether got enough shares
		if  _, ok := self.encryptedSet[A]; !ok || len(shares) < requires {
			continue
		}

		bA, err := sssa.CombineECDSAPubkey(shares)				//bA
		if err != nil {
			fmt.Println("Fatal: combining: ", err)
			continue
		}

		hash := crypto.Keccak256(crypto.FromECDSAPub(bA))        //hash([b]A)
		fmt.Println("hash:::::::::::::::::::::", hexutil.Encode(hash[:]))
		privECDSA, _ := crypto.ToECDSA(hash)
		pub:=common.ToHex(crypto.FromECDSAPub(&privECDSA.PublicKey))
		fmt.Println("pub--------------------------->",pub)


		priv := ecies.ImportECDSA(privECDSA)

		fmt.Println("encrypted pub=============", common.ToHex(crypto.FromECDSAPub(&privECDSA.PublicKey)))

		//Decryption
		fmt.Printf("encryptedSet %x\n", self.encryptedSet[A])

		//ct, _ := hex.DecodeString(self.encryptedSet[A])
		ct :=[]byte(self.encryptedSet[A])
		//fmt.Printf("ct %x\n", ct)
		pt, err := priv.Decrypt(rand.Reader, ct, nil, nil)
		if err != nil {
			fmt.Println("decryption: ", err.Error())
			continue
		}
		fmt.Println(string(pt))

		//Confirm stat with the contract
		self.verifiedSet[A] = self.pendingSet[A]
		self.VerifiedChan <- A
		delete(self.pendingSet, A)
		delete(self.encryptedSet, A)
		delete(self.shareSet, A)
	}
}
