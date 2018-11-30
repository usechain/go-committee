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
	"fmt"
	"math/big"
	"crypto/ecdsa"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/contract/identity"
	"github.com/usechain/go-committee/node/config"
)


// Simple history verify msg storage & check
var CertIDMap = make(map[string]*big.Int)		// a1s1 ---> certID
var MsgCountMap = make(map[string]int)      // a1s1 ---> received count, 0x001 for id 1 received, 0x011 for id 1 & 2 received
var MsgMap = make(map[string][]string)		 // hash(a1s1 + senderid) --> verify shares

func SaveVerifyMsg(certid *big.Int, a1s1 string, senderId int, shares []string, requires int) {
	if c, _ := utils.BitCount(MsgCountMap[a1s1]); c >= requires {
		return
	}
	CertIDMap[a1s1] = certid
	MsgCountMap[a1s1] = MsgCountMap[a1s1] | (senderId+1)
	index := crypto.Keccak256Hash([]byte(a1s1 + string(senderId+1)))
	MsgMap[index.Hex()] = shares
}

func CheckVerifyMsg(usechain *config.Usechain, requires int) {
	for a1s1, value := range MsgCountMap {
		fmt.Println("value", int(value))

		//check whether got enough shares
		if c, idset := utils.BitCount(int(value)); c >= requires {
			//extract the a1s1
			sbyte,_:=hexutil.Decode("0x" + a1s1)
			A1, S1, err := keystore.GeneratePKPairFromABaddress(sbyte[:])

			if err !=nil {
				log.Debug("A1S1 decode failed!", err)
				return
			}

			// store all possible pub share permutation
			var tmpset [][]string
			for _, id := range idset {
				index := crypto.Keccak256Hash([]byte(a1s1 + string(id)))
				tmpset = append(tmpset, MsgMap[index.Hex()])
			}

			//check whether got a proper keyshare right for A1 = [Hash(bA)]G + S
			pubshares := utils.PermutationStrings(tmpset)
			var tmpKey ecdsa.PublicKey
			for _, share := range pubshares {
				pub, err := sssa.CombineECDSAPubkey(share)
				if err != nil {
					fmt.Println("Fatal: combining: ", err)
				}

				tmpKey = sssa.ScanPubSharesA1(pub, S1)
				if tmpKey.X.Cmp(A1.X) == 0&& tmpKey.Y.Cmp(A1.Y) == 0 {
					fmt.Println("legal address")
					///TODO:send confirm tx to contract

					identity.SendAuthenticationConfirm(usechain, CertIDMap[a1s1], true)
					break
				}
			}
		}
	}
}

