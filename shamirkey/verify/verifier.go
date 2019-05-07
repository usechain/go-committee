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

package verify

import (
	"math/big"
	"github.com/usechain/go-committee/shamirkey/core"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
)

// Return the verfier id set based on the A address
func AccountVerifier(A string, max int) (idset []int) {
	hash := crypto.Keccak256Hash([]byte(A))
	id := big.NewInt(0).Mod(hash.Big(), big.NewInt(int64(max)))

	for i := 0; i < core.VerifierRequires; i++ {
		index := (int(id.Int64()) + i)%max
		idset = append(idset, index)
	}
	log.Info("AccountVerifier committee ID set", "idset", idset)
	return
}

// Check the determined ID whether need to verify the address A
func IsAccountVerifier(addrID string, max int, cid int) bool {
	idset := AccountVerifier(addrID, max)
	for _, id := range idset {
		if id == cid {
			return true
		}
	}
	return false
}

// Return the verfier id set based on the A address
func AccountSubVerifier(A string, max int) (idset []int) {
	hash := crypto.Keccak256Hash([]byte(A))
	id := big.NewInt(0).Mod(hash.Big(), big.NewInt(int64(max)))

	for i := 0; i < core.VerifierSubRequires; i++ {
		index := (int(id.Int64()) + i)%max
		idset = append(idset, index)
	}
	log.Info("AccountVerifier committee ID set", "idset", idset)
	return
}

// Check the determined ID whether need to verify the address A
func IsSubAccountVerifier(A string, max int, cid int) bool {
	idset := AccountSubVerifier(A, max)
	for _, id := range idset {
		if id == cid {
			return true
		}
	}
	return false
}

