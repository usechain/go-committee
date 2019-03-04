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

package manager

import (
	"fmt"
	"math/big"
	"reflect"
	"encoding/hex"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/node/config"
	"crypto/ecdsa"
)

func GetSelfCommitteeID(config config.Usechain) (int, error){
	rpc := config.NodeRPC
	ctr := config.ManagerContract
	coinbase := config.UserProfile.Address

	//Check whether a real committee
	res, err := ctr.ContractCallParsed(rpc, coinbase, "getCommitteeIndex")
	if err != nil {
		fmt.Println("read unconfirmed address failed",  err)
		return -1, err
	}
	fmt.Println("res", res)
	certID, ok := (res[0]).(*big.Int)
	if !ok {
		log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
		return -1, err
	}
	return int(certID.Int64()), nil
}


func ConfirmAndKeyUpload(config config.Usechain) {
	rpc := config.NodeRPC
	ctr := config.ManagerContract
	ks := config.Kstore

	b, err := hex.DecodeString(config.WisperInfo.Key)
	if err != nil {
		log.Error("Failed to load whisper default key.", "err", err)
		return
	}
	asymKey, err := crypto.ToECDSA(b)
	if err != nil {
		log.Error("Failed to load whisper default key.", "err", err)
		return
	}

	res, err := ctr.ContractTransaction(rpc, ks, config.UserProfile.Address, "confirmAndKeyUpload", common.ToHex(crypto.FromECDSAPub(&asymKey.PublicKey)))
	if err != nil {
		log.Error("confirmAndKeyUpload",  "err", err)
		return
	}
	log.Info("the confirmAndKeyUpload transaction", "Hash", res)

}

func UploadCommitteePublickey(config *config.Usechain, key *ecdsa.PublicKey) {
	rpc := config.NodeRPC
	ctr := config.ManagerContract
	ks := config.Kstore

	keyStr := crypto.FromECDSAPub(key)
	res, err := ctr.ContractTransaction(rpc, ks, config.UserProfile.Address, "uploadCommitteePubkey", common.ToHex(keyStr))
	if err != nil {
		log.Error("uploadCommitteePubkey",  "err", err)
		return
	}
	log.Info("the uploadCommitteePubkey transaction", "Hash", res)
}