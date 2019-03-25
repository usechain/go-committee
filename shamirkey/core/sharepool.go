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
	"crypto/rand"
	"sync"
	//"encoding/hex"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/ecies"
	"github.com/usechain/go-usechain/common/hexutil"
	"time"
	"encoding/json"
	"strings"
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

type UserData struct {
	Id       string `json:"id"`
	CertType string `json:"certtype"`
	Sex      string `json:"sex"`
	Name     string `json:"name"`
	EName    string `json:"ename"`
	Nation   string `json:"nation"`
	Addr     string `json:"addr"`
	BirthDay string `json:"birthday"`
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

func (self *SharePool) GetVerifiedCertHash(key string) common.Hash {
	return self.verifiedSet[key]
}

func (self *SharePool) SaveAccountSharedCache(A string, bsA string, id int) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.shareSet[A] = append(self.shareSet[A], bsA)
}

func (self *SharePool) SaveEncryptedData(A string, h common.Hash, data string) {
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
			time.Sleep(time.Second * 10)
			log.Error("Combine error: ", "error", err)
			continue
		}

		hash := crypto.Keccak256(crypto.FromECDSAPub(bA))        //hash([b]A)

		log.Debug("Received Hash", hexutil.Encode(hash[:]))
		privECDSA, _ := crypto.ToECDSA(hash)

		pub:=common.ToHex(crypto.FromECDSAPub(&privECDSA.PublicKey))
		log.Debug("Received Publick key",pub)

		priv := ecies.ImportECDSA(privECDSA)

		//Decryption
		decrypedAndVerifyData := strings.Split(self.encryptedSet[A], "+")
		ct,err :=hexutil.Decode(decrypedAndVerifyData[1])
		if err != nil {
			log.Error("Decode encdata", "err", err)
		}
		pt, err := priv.Decrypt(rand.Reader, ct, nil, nil)
		if err != nil {
			log.Error("decryption: ", err.Error())
			continue
		}

		userData := UserData{}
		err = json.Unmarshal(pt, &userData)
		if err != nil{
			log.Debug( "Unmarshal failed: " , "err", err )
		}

		id := userData.CertType + "-" + userData.Id
		idHash :=hexutil.Encode(crypto.Keccak256Hash([]byte(id)).Bytes())
		if idHash != decrypedAndVerifyData[0] {
			log.Error("Verify certHash and verifyHash failed")
			return
		}
		log.Info("Decrypt received shared message", "msg", string(pt))

		//Confirm stat with the contract
		self.verifiedSet[A] = self.pendingSet[A]
		self.VerifiedChan <- A
		delete(self.pendingSet, A)
		delete(self.encryptedSet, A)
		delete(self.shareSet, A)
	}
}
