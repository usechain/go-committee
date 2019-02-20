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

package shamirkey

import (
	"math/big"
	"fmt"
	"github.com/usechain/go-usechain/crypto"
)

// Return the verfier id set based on the A address
func AccountVerifier(A string, max int) (idset []int) {
	hash := crypto.Keccak256Hash([]byte(A))
	id := big.NewInt(0).Mod(hash.Big(), big.NewInt(int64(max)))

	for i := 0; i < verifierRequires; i++ {
		index := (int(id.Int64()) + i)%max
		idset = append(idset, index)
	}
	fmt.Println("idset", idset)
	return
}

// Check the determined ID whether need to verify the address A
func IsAccountVerifier(A string, max int, cid int) bool {
	idset := AccountVerifier(A, max)
	for _, id := range idset {
		if id == cid {
			return true
		}
	}
	return false
}