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
	"time"
	"encoding/json"
	"strings"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"

	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/ecies"
	"github.com/usechain/go-usechain/common/hexutil"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"crypto/ecdsa"
)

const chanSizeLimit = 10

type SharePool struct {
	shareSet 		 map[string][]string
	encryptedSet	 map[string]string
	pendingSet		 map[string]common.Hash
	verifiedSet		 map[string]common.Hash
	VerifiedChan	 chan string

	encryptedSubSet  map[string]string
	pendingSubSet	 map[string]string
	verifiedSubSet	 map[string]string
	VerifiedSubChan  chan string
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

func (self *SharePool) SaveEncryptedSub(A string, data string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.encryptedSubSet[A] = data
	self.pendingSubSet[A] = data
}

func (self *SharePool) CheckSharedMsg(usechain *config.Usechain, requires int) {
	self.mu.Lock()
	defer self.mu.Unlock()
	for A, shares := range self.shareSet {
		//check whether got enough shares
		if len(shares) < requires {
			continue
		}
		bA, err := sssa.CombineECDSAPubkey(shares) //bA
		if err != nil {
			time.Sleep(time.Second * 10)
			log.Error("Combine error: ", "error", err)
			continue
		}

		hash := crypto.Keccak256(crypto.FromECDSAPub(bA)) //hash([b]A)

		log.Debug("Received Hash bA", "hash(bA)", hexutil.Encode(hash[:]))
		privECDSA, _ := crypto.ToECDSA(hash)

		pub := common.ToHex(crypto.FromECDSAPub(&privECDSA.PublicKey))
		log.Debug("Received Publick key", "pub", pub)

		priv := ecies.ImportECDSA(privECDSA)

		if _, ok := self.encryptedSet[A]; ok {
			//Decryption
			decrypedAndVerifyData := strings.Split(self.encryptedSet[A], "+")
			ct, err := hexutil.Decode(decrypedAndVerifyData[1])
			if err != nil {
				log.Error("Decode encdata", "err", err)
			}

			pt, err := priv.Decrypt(rand.Reader, ct, nil, nil)
			if err != nil {
				log.Error("decryption: ", "err", err.Error())
				continue
			}

			userData := UserData{}
			err = json.Unmarshal(pt, &userData)
			if err != nil {
				log.Debug("Unmarshal failed: ", "err", err)
			}

			id := userData.CertType + "-" + userData.Id
			idHash := hexutil.Encode(crypto.Keccak256Hash([]byte(id)).Bytes())
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

		if data, ok := self.encryptedSubSet[A]; ok {
			//Decryption
			ct, err := hexutil.Decode(data)
			if err != nil {
				log.Error("Decode sub encdata", "err", err)
			}

			pt, err := priv.Decrypt(rand.Reader, ct, nil, nil)
			if err != nil {
				log.Error("decryption: ", "err", err.Error())
				continue
			}
			log.Info("Decrypt received shared message", "msg", string(pt))

			A1, S1, err := GeneratePKPairFromSubAddress(pt)
			if err !=nil {
				log.Error("GeneratePKPairFromSubAddress", "err", err)
			}
			A11:=common.ToHex(crypto.FromECDSAPub(A1))
			S11:=common.ToHex(crypto.FromECDSAPub(S1))

			fmt.Println("A1:::", A11)
			fmt.Println("S1---===", S11)

			pub := generateH(A1, S1, privECDSA)
			AA := common.ToHex(crypto.FromECDSAPub(&pub))
			if AA == A {
				//Confirm stat with the contract
				self.verifiedSubSet[A] = self.verifiedSubSet[A]
				self.VerifiedSubChan <- A
				delete(self.pendingSubSet, A)
				delete(self.encryptedSubSet, A)
				delete(self.shareSet, A)
			}
		}
	}
}

func GeneratePKPairFromSubAddress(w []byte) (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {
	if len(w) != 66 {
		fmt.Println(len(w))
		return nil, nil, nil
	}

	tmp := make([]byte, 33)
	copy(tmp[:], w[:33])
	curve := btcec.S256()
	PK1, err := btcec.ParsePubKey(tmp, curve)
	if err != nil {
		//这里遇到错误：tmp全是0：invalid magic in compressed pubkey string: 0
		return nil, nil, err
	}

	copy(tmp[:], w[33:])
	PK2, err := btcec.ParsePubKey(tmp, curve)
	if err != nil {
		return nil, nil, err
	}

	PK11:=(*ecdsa.PublicKey)(PK1)
	PK22:=(*ecdsa.PublicKey)(PK2)
	return PK11, PK22, nil
}

// generateH generate one public key of AB account by using algorithm A1=[hash([b]A)]G+S
func generateH(A *ecdsa.PublicKey, S *ecdsa.PublicKey, b *ecdsa.PrivateKey) ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)

	A1.X, A1.Y = crypto.S256().ScalarMult(A.X, A.Y, b.D.Bytes()) //A1=[b]A

	A1Bytes := crypto.Keccak256(crypto.FromECDSAPub(A1)) //hash([b]A)

	A1.X, A1.Y = crypto.S256().ScalarBaseMult(A1Bytes) //[hash([a]B)]G

	A1.X, A1.Y = crypto.S256().Add(A1.X, A1.Y, S.X, S.Y) //A1=[hash([a]B)]G+S
	A1.Curve = crypto.S256()
	return *A1
}
