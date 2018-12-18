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

package identity

import (
	"fmt"
	"math/big"
	"reflect"
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/msg"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
	"crypto/ecdsa"
)
var (
	CertIDLastCached = big.NewInt(0)		//the last handled account authentication certid
)

//The struct of the address detail info
type AddressList struct {
	Added 			bool
	Confirmed 		bool
	AddressType 	uint8
	RingSig 		string
	PubSKey 		string
	PublicKeyMirror string
}

//Unpack the contract output to type.AddressList
func InterfaceTransAddressList(listers []interface{}) (*AddressList, error) {
	var list AddressList
	var ok bool

	list.Added, ok = (listers[0]).(bool)
	if !ok {
		return nil, fmt.Errorf("it's not ok for type bool")
	}

	list.Confirmed , ok  = (listers[1]).(bool)
	if !ok {
		return nil, fmt.Errorf("it's not ok for type bool")
	}

	list.AddressType, ok  = (listers[2]).(uint8)
	if !ok {
		return nil, fmt.Errorf("it's not ok for type uint8")
	}

	list.RingSig, ok = (listers[3]).(string)
	if !ok {
		return nil, fmt.Errorf("it's not ok for type string")
	}

	list.PubSKey, ok = (listers[4]).(string)
	if !ok {
		return nil, fmt.Errorf("it's not ok for type string")
	}

	list.PublicKeyMirror, ok = (listers[5]).(string)
	if !ok {
		return nil, fmt.Errorf("it's not ok for type string")
	}
	return &list, nil
}


func SendAuthenticationConfirm(usechain *config.Usechain, certID *big.Int, flag bool) {
	rpc := usechain.NodeRPC
	idctr := usechain.IdentityContract
	coinbase := usechain.UserProfile.Address
	ks := usechain.Kstore

	res, err := idctr.ContractTransaction(rpc, ks, coinbase,"confirmCert", certID, flag)
	if err != nil {
		log.Error("confirmCert",  "err", err)
		return
	}
	log.Info("confirmCert", "res", res)
}



func ScanIdentityAccount(usechain *config.Usechain, priv *ecdsa.PrivateKey, nodelist []string) {
	rpc := usechain.NodeRPC
	idctr := usechain.IdentityContract
	coinbase := usechain.UserProfile.Address
	id := usechain.UserProfile.CommitteeID

	// get unconfirmed address number
	res, err := idctr.ContractCall(rpc, coinbase, "unConfirmedAddressLen")
	if err != nil {
		log.Error("contract call", "err", err)
		return
	}
	if res == contract.ContractZero {
		return
	}

	unconfirmedCount, _ := big.NewInt(0).SetString(res[2:], 16)
	log.Debug("unconfirmedcount", "count", unconfirmedCount)
	for i := int64(0); i < unconfirmedCount.Int64(); i++ {
		// get unconfirmed address index
		res, err := idctr.ContractCallParsed(rpc, coinbase,"unConfirmedAddress", big.NewInt(35))
		if err != nil {
			log.Error("read unconfirmed address failed",  "err", err)
			return
		}
		certID, ok := (res[0]).(*big.Int)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
			return
		}
		// If already checked, pass it
		if certID.Cmp(CertIDLastCached) != 1 {
			continue
		}

		log.Debug("Check a new account verifying")
		// get address based on cert id as index
		res, err = idctr.ContractCallParsed(rpc, coinbase,"CertToAddress", certID)
		if err != nil {
			log.Error("ContractCallParsed failed", "err", err)
			return
		}
		value, ok := (res[1]).(common.Address)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[1]))
			return
		}
		//fmt.Println("addr", value)

		// get address detail info based on address as index
		res, err = idctr.ContractCallParsed(rpc, coinbase,"CertificateAddr", value)
		if err != nil {
			log.Error("ContractCallParsed failed", "err", err)
			return
		}

		addrlist, err := InterfaceTransAddressList(res)
		//fmt.Println("addrlist", addrlist, err)

		err, pubSet, _, _, _ := crypto.DecodeRingSignOut(addrlist.RingSig)
		if err != nil {
			log.Error("RingSig decode failed!", err)
		}

		//for i := range pubSet {
		//	fmt.Println("+++++++", pubSet[i])
		//}

		m := msg.PackAccountVerifyShare(certID, pubSet, addrlist.PubSKey, priv, id)
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(nodelist[0])))

		//update the CertIDLastCached
		CertIDLastCached = certID
	}
}

