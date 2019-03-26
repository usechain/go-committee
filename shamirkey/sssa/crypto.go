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

package sssa

import (
	"math/big"
	"crypto/ecdsa"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/subchain/log"
)

type PrivateShare struct {
	Index 	*big.Int
	Key 	*big.Int
}

// Import an privateShare
func NewPrivateShare(share string) *PrivateShare {
	// ...ensure that it is valid...
	if IsValidShare(share) == false {
		return nil
	}
	index := utils.FromBase64(share[0:44])
	key := utils.FromBase64(share[44:88])
	return &PrivateShare{
		Index:      index,
		Key:		key,
	}
}

//Generate private key from a big.int
func generatePrivKey(key *big.Int) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	priv.D = key.Mod(key, crypto.S256().Params().N)
	priv.PublicKey.X, priv.PublicKey.Y = crypto.S256().ScalarBaseMult(key.Bytes())

	return priv
}

func GeneratePrivKey(key *big.Int) *ecdsa.PrivateKey {
	return generatePrivKey(key)
}

//Extract private share from string
func ExtractPrivateShare(privshare string) *ecdsa.PrivateKey {
	// ...ensure that it is valid...
	if IsValidShare(privshare) == false {
		log.Error("ExtractPrivateShare failed", "error", false)
		return nil
	}
	priv := utils.FromBase64(privshare[44:])
	return generatePrivKey(priv)
}

// GenerateA1 generate one pulic key of AB account
// A1=[hash([b]A)]G+S
func ScanPubSharesA1(bA *ecdsa.PublicKey, S *ecdsa.PublicKey) ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)
	A1.X = bA.X
	A1.Y = bA.Y

	A1Bytes := crypto.Keccak256(crypto.FromECDSAPub(A1))        //hash([a]B)
	A1.X, A1.Y = crypto.S256().ScalarBaseMult(A1Bytes)   //[hash([a]B)]G
	A1.X, A1.Y = crypto.S256().Add(A1.X, A1.Y, S.X, S.Y) //A1=[hash([a]B)]G+S
	A1.Curve = crypto.S256()
	return *A1
}


//Generate public key array from a private big.int keys array
func ToECDSAPubArray(privs []*big.Int) []*ecdsa.PublicKey {
	var privkeys []*ecdsa.PrivateKey = make([]*ecdsa.PrivateKey, len(privs))
	var pubkeys []*ecdsa.PublicKey = make([]*ecdsa.PublicKey, len(privs))
	for i := 0; i < len(privs); i++ {
		privkeys[i] = generatePrivKey(privs[i])
		pubkeys[i] = &privkeys[i].PublicKey
	}

	return pubkeys
}

//Check two public key whether are same ones
func equalECDSAPub(p1 *ecdsa.PublicKey, p2 *ecdsa.PublicKey) bool {
	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) ==0 {
		return true
	}
	return false
}
