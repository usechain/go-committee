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
	"crypto/ecdsa"
	"time"
	"math/big"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/contract/manager"
)

type KeyPool struct {
	polySet 		 [][]*ecdsa.PublicKey
	keySet			 []string

	keycache		 []string
}

func NewKeyPool() *KeyPool{
	return &KeyPool{
		polySet:		make([][]*ecdsa.PublicKey, CommitteeMax),
		keySet:  		make([]string, CommitteeMax),
	}
}

// Return the actual x point for shamir's share
func point(id int) int {
	return id + 1
}

func (self *KeyPool) KeyCache(id int) string{
	return self.keycache[id]
}

func (self *KeyPool) InsertPolynomialShare(id int, keys []*ecdsa.PublicKey) {
	self.polySet[id] = keys
	return
}

func (self *KeyPool) InsertPrivateKeyShare(id int, key string) {
	self.keySet[id] = key
	return
}

func (self *KeyPool) InsertKeyCache(cache string) {
	self.keycache = append(self.keycache, cache)
	return
}

func (self *KeyPool) Cachelen() int{
	return len(self.keycache)
}

func (self *KeyPool) getCacheByIndex(index int) string {
	return self.keycache[index]
}

// Check whether get enough shares, and try to generate the multi-sssa private key
func (self *KeyPool) ShamirKeyShareCheck(usechain *config.Usechain) {
	successFlag := false
	for !successFlag {
		for i := range self.polySet {
			if self.keySet[i] == "" || len(self.polySet[i]) == 0{
				break
			}

			if !sssa.VerifyPolynomial(self.keySet[i], self.polySet[i]) {
				break
			}
			if i == len(self.polySet) - 1 {
				successFlag = true
			}
		}
		time.Sleep(time.Second * 1)
	}

	id := usechain.UserProfile.CommitteeID
	priv := sssa.GenerateSssaKey(self.keySet)
	log.Debug("keyset===========", "keyset", self.keySet)
	res := utils.ToBase64(big.NewInt(int64(point(id))))
	res += utils.ToBase64(priv)

	//update global config
	usechain.UserProfile.PrivShares = res

	//update local profile
	p, _ := config.ReadProfile()
	p.PrivShares = res
	config.UpdateProfile(p)
	log.Warn("key shares generated", "id" , id, "key", res)

	//Upload committee key
	pubkey := sssa.GenerateCommitteePublicKey(self.polySet)
	manager.UploadCommitteePublickey(usechain, pubkey)
}
