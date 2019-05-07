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
	"encoding/hex"
	"time"
	"strconv"
	"math/big"
)

const chanSizeLimit = 10

type VerifiedMain struct {
	RegisterID *big.Int
	Hashkey common.Hash
	Status  *big.Int
}

type VerifiedSub struct {
	RegisterID *big.Int
	Status  *big.Int
}

type SharePool struct {
	shareSet 		 map[string][]string
	encryptedSet	 map[string]string
	pendingSet		 map[string]common.Hash
	verifiedSet		 map[string]common.Hash
	VerifiedChan	 chan VerifiedMain

	encryptedSubSet  map[string]string
	pendingSubSet	 map[string]string
	verifiedSubSet	 map[string]string
	VerifiedSubChan  chan VerifiedSub

	encryptedHSet  map[string][]string
	pendingHSet	 map[string][]string
	verifiedHSet	 map[string][]string

	SubChan		chan *SubData

	SubFailedDecrypted chan string
	mu 				 sync.Mutex
}

type SubData struct {
	SubID string
	H string
	Amain string
	S string
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
		VerifiedChan:make(chan VerifiedMain, chanSizeLimit),

		encryptedSubSet: make(map[string]string),
		pendingSubSet: make(map[string]string),
		verifiedSubSet: make(map[string]string),
		VerifiedSubChan:make(chan VerifiedSub, chanSizeLimit),
		SubChan:make(chan *SubData, chanSizeLimit),

		encryptedHSet : make(map[string][]string),
		pendingHSet : make(map[string][]string),
		verifiedHSet: make(map[string][]string),
		SubFailedDecrypted : make(chan string, chanSizeLimit),
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

func (self *SharePool) SaveEncryptedData(addrID string, h common.Hash, data string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.encryptedSet[addrID] = data
	self.pendingSet[addrID] = h
}

func (self *SharePool) SaveEncryptedSub(addrSubIDstring string, data string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.encryptedSubSet[addrSubIDstring] = data
	self.pendingSubSet[addrSubIDstring] = data
}

func (self *SharePool) SaveSubData(S string, H string, subID string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.encryptedHSet[S] =  append(self.encryptedHSet[S], H)
	self.encryptedHSet[S] = append(self.encryptedHSet[S], S)
	self.encryptedHSet[S] = append(self.encryptedHSet[S], subID)
	fmt.Println("encryptedHSet======", self.encryptedHSet)
}

func (self *SharePool) CheckSharedMsg(usechain *config.Usechain, requires int) {
	self.mu.Lock()
	defer self.mu.Unlock()
	for A, shares := range self.shareSet {
		//check whether got enough shares
		if len(shares) < 5 {
			time.Sleep(time.Second)
			continue
		}
		log.Info("Received shares", "len(shares)", len(shares))

		bA, err := sssa.CombineECDSAPubkey(shares) //bA
		if err != nil {
			log.Error("Combine error: ", "error", err)
			delete(self.shareSet, A)
			continue
		}

		hash := crypto.Keccak256(crypto.FromECDSAPub(bA)) //hash([b]A)

		log.Debug("Generate Hash bA", "hash(bA)", hexutil.Encode(hash[:]))
		privECDSA, _ := crypto.ToECDSA(hash)

		//pub := common.ToHex(crypto.FromECDSAPub(&privECDSA.PublicKey))
		//log.Debug("Generate Publick key", "pub", pub)

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
				delete(self.pendingSet, A)
				delete(self.encryptedSet, A)
				delete(self.shareSet, A)
				continue
			}

			userData := UserData{}
			err = json.Unmarshal(pt, &userData)
			if err != nil {
				log.Debug("Unmarshal failed: ", "err", err)
			}

			id := userData.CertType + "-" + userData.Id
			idHash := hexutil.Encode(crypto.Keccak256Hash([]byte(id)).Bytes())
			var status int64
			if idHash != decrypedAndVerifyData[0] {
				log.Error("Verify certHash and verifyHash failed")
				status = 4
			}

			log.Info("Decrypt received shared message", "msg", string(pt))
			status = 3
			regID, err := strconv.Atoi(A)
			if err != nil {
				fmt.Println("registerID error", err)
			}

			verifiedData := VerifiedMain{
				RegisterID: big.NewInt(int64(regID)),
				Hashkey: common.HexToHash(decrypedAndVerifyData[0]),
				Status: big.NewInt(status),
			}
			//Confirm stat with the contract
			self.verifiedSet[A] = self.pendingSet[A]
			self.VerifiedChan <- verifiedData
			delete(self.pendingSet, A)
			delete(self.encryptedSet, A)
		}

		if subData, ok := self.encryptedSubSet[A]; ok {
			data := strings.Split(subData, "+")
			//Decryption
			ct, err := hexutil.Decode(data[1])
			if err != nil {
				log.Error("Decode sub encdata", "err", err)
			}

			pt, err := priv.Decrypt(rand.Reader, ct, nil, nil)
			if err != nil {
				log.Error("decryption sub encAS: ", "err", err)
				// TODO:   SubFailedDecrypted 添加到合约
				for Ax , _ := range self.shareSet{
					fmt.Println("lets see shareSet+++++++++++++++++++", Ax)
				}
				for Ax , bx := range self.encryptedSubSet{
					fmt.Println("lets see encryptedSubSet+++++++++++++++++++", Ax,bx)
				}
				//self.SubFailedDecrypted <- A
				delete(self.shareSet, A)
				continue
			}

			log.Info("Decrypt received subaccount shared message", "msg", string(pt))
			ASbyte, _ := hex.DecodeString(string(pt))
			A1, S1, err := GeneratePKPairFromSubAddress(ASbyte)
			if err != nil {
				log.Error("GeneratePKPairFromSubAddress", "err", err)
				continue
			}

			A11 := common.ToHex(crypto.FromECDSAPub(A1))
			S11 := common.ToHex(crypto.FromECDSAPub(S1))
			fmt.Println("A1:::", A11)
			fmt.Println("S1---===", S11)

			if A1 != nil && S1 != nil {
				subdata := &SubData{
					SubID: A,
					H: data[0],
					Amain: A11,
					S: S11,
				}
				self.SubChan <- subdata
				self.verifiedSubSet[A] = self.pendingSubSet[A]
			}
			delete(self.pendingSubSet, A)
			delete(self.encryptedSubSet, A)

			//pub := generateH(S1, privECDSA)
			//AA := common.ToHex(crypto.FromECDSAPub(&pub))
			//fmt.Println("A1=[hash([a]B)]G+S", AA)
			//if AA != A {
			//	log.Error("Verify sub account failed")
			//	return
			//}
			////Confirm stat with the contract
			//self.VerifiedSubChan <- A
		}

		if HSverify, ok := self.encryptedHSet[A]; ok {
			log.Info("Received sub account shared message", "msg",  self.encryptedHSet)
			Sbyte, err := hexutil.Decode(HSverify[1])
			if err != nil {
				log.Error("encryptedHSet", "err", err)
				continue
			}
			subS := crypto.ToECDSAPub(Sbyte)
			genH := generateH(subS, hash)
			genHstring := common.ToHex(crypto.FromECDSAPub(&genH))
			log.Info("Generate sub account pubkey", "subPub", genHstring)
			var status int64
			if HSverify[0] == genHstring {
				log.Info("Verified sub account: valid! ", "subPub", HSverify[0])
				status = 3
			}
			status = 4
			fmt.Println("verified sub address ID", HSverify[2])
			regiID, err := strconv.Atoi(HSverify[2])
			if err != nil {
				fmt.Println("registerID error", err)
			}
			verifiedSub := VerifiedSub{
				RegisterID: big.NewInt(int64(regiID)),
				Status: big.NewInt(status),
			}
			self.VerifiedSubChan <- verifiedSub

			self.verifiedHSet[A] = self.pendingHSet[A]
			delete(self.pendingHSet, A)
			delete(self.encryptedHSet, A)
		}
		delete(self.shareSet, A)
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
func generateH(S *ecdsa.PublicKey, hashbA []byte) ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)

	A1.X, A1.Y = crypto.S256().ScalarBaseMult(hashbA) //[hash([a]B)]G

	A1.X, A1.Y = crypto.S256().Add(A1.X, A1.Y, S.X, S.Y) //A1=[hash([a]B)]G+S
	A1.Curve = crypto.S256()
	return *A1
}
