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
	"reflect"
	"crypto/ecdsa"
	"time"
	"math/big"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-committee/contract/identity"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/shamirkey/msg"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/contract/manager"
)

var (
	CommitteeMax = 3
	CommitteeRequires = 2
	CommitteeNodeList []string		// CommitteeNodeList[0] is the verifier
									// Verifier isn't include in CommitteeMax&CommitteeRequires
									// Verifier got 1st votes in election， are the committees[0] logged in contract
									// All sharer pack shares send to verifier
)

var (
	PolynomialArray [][]*ecdsa.PublicKey = make([][]*ecdsa.PublicKey, CommitteeMax)
	PrivateKeyShare []string = make([]string, CommitteeMax)
)


//Read committee config from contract
func InitShamirCommitteeNumber(config config.Usechain) {
	rpc := config.NodeRPC
	ctr := config.ManagerContract
	coinbase := config.UserProfile.Address

	//Check whether a real committee
	res, err := ctr.ContractCallParsed(rpc, coinbase, "MAX_COMMITTEEMAN_COUNT")
	if err != nil {
		fmt.Println("read MAX_COMMITTEEMAN_COUNT failed",  err)
		return
	}
	max, ok := (res[0]).(*big.Int)
	if !ok {
		log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
		return
	}

	//Check whether a real committee
	res, err = ctr.ContractCallParsed(rpc, coinbase, "Requirement")
	if err != nil {
		fmt.Println("read Requirement failed",  err)
		return
	}
	min, ok := (res[0]).(*big.Int)
	if !ok {
		log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
		return
	}

	CommitteeMax = int(max.Int64())
	CommitteeRequires = int(min.Int64())

	for i := 0; i < CommitteeMax; i++ {
		//Get committee asym key
		res, err = ctr.ContractCallParsed(rpc, coinbase, "getCommitteeAsymkey", big.NewInt(int64(i)))
		if err != nil {
			fmt.Println("read committee failed",  err)
			return
		}
		asym, ok := (res[0]).(string)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
			return
		}
		CommitteeNodeList = append(CommitteeNodeList, asym)
	}
	log.Debug("CommitteeNodeList", "list", CommitteeNodeList)
}

func ShamirKeySharesGenerate(id int) {
	// committee generate a random number, di
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Crit(fmt.Sprintf("Failed to generate ephemeral node key: %v", err))
	}
	fmt.Println("******priv******", priv.D)

	// generate shares
	created, _, polynomials, err := sssa.Create256Bit(2,3, priv.D)
	if err != nil {
		log.Error("err", err)
		return
	}
	combined, err := sssa.Combine256Bit(created)
	if err != nil || combined.Cmp(priv.D) != 0 {
		log.Error("Fatal: combining: ", err)
	}

	polyPublicKeys := sssa.ToECDSAPubArray(polynomials)

	if !sssa.VerifyCreatedAndPolynomial(created, polyPublicKeys) {
		log.Error("Fatal: verifying: ", err)
	}

	// broadcast the shares
	m := msg.PackPolynomialShare(polyPublicKeys, id)
	wnode.SendMsg(m, nil)

	// send f(j) to j committee
	for i:= range CommitteeNodeList {
		if i == 0 {
			continue
		}
		m = msg.PackKeyPointShare(created[i-1], id)
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(CommitteeNodeList[i])))
	}
}

// Broadcast NewCommitteeLogInMsg,  request for sharing keys
func SendRequesuShares(senderid int) {
	m := msg.PackCommitteeNewLogin(senderid)
	wnode.SendMsg(m, nil)
}

// Listening the network msg
func ShamirKeySharesListening(p *config.CommittteeProfile) {
	log.Debug("Listening...")
	var input []byte

	for {
		input = <-wnode.ChanWhisper

		m, err := msg.UnpackMsg(input)
		if err != nil {
			fmt.Println("Unknown msg type")
			continue
		}

		if p.Role == "Verifier" && m.Type != msg.SubAccountVerifyMsg {
			continue
		}

		switch m.Type {
		case msg.PolynomialShare:
			log.Debug("received polynomial shares")
			PolynomialArray[m.Sender-1] = msg.UnpackPolynomialShare(m.Data)
		case msg.Keyshare:
			log.Debug("received key shares")
			PrivateKeyShare[m.Sender-1] = string(m.Data[0])
		case msg.NewCommitteeLogInMsg:
			log.Debug("detected a new logged in committee")
			ShamirKeySharesGenerate(p.CommitteeID)
		case msg.SubAccountVerifyMsg:
			certID, pubshares, pubSkey := msg.UnpackAccountVerifyShare(m.Data)
			log.Debug("received a new account verify msg", "certID", certID)
			SaveVerifyMsg(certID, pubSkey, m.Sender, pubshares, CommitteeRequires)
		}
	}
}

// Check whether get enough shares, and try to generate the multi-sssa private key
func ShamirKeyShareCheck(usechain *config.Usechain) {
	successFlag := false
	for !successFlag {
		for i := range PolynomialArray {
			if PrivateKeyShare[i] == "" || len(PolynomialArray[i]) == 0{
				break
			}

			if !sssa.VerifyPolynomial(PrivateKeyShare[i], PolynomialArray[i]) {
				break
			}
			if i == len(PolynomialArray) - 1 {
				successFlag = true
			}
		}
		time.Sleep(time.Second * 1)
	}

	id := usechain.UserProfile.CommitteeID
	priv := sssa.GenerateSssaKey(PrivateKeyShare)
	res := utils.ToBase64(big.NewInt(int64(id)))
	res += utils.ToBase64(priv)

	//update global config
	usechain.UserProfile.PrivShares = res

	//update local profile
	p, _ := config.ReadProfile()
	p.PrivShares = res
	config.UpdateProfile(p)
	log.Warn("key shares generated", "key", res)

	//Upload committee key
	pubkey := sssa.GenerateCommitteePublicKey(PolynomialArray)
	manager.UploadCommitteePublickey(usechain, pubkey)

}

//The sharer scan the identity contract, and sign the account's share by its own private key
func AccountShareSharer(usechain *config.Usechain) {
	priv := sssa.ExtractPrivateShare(usechain.UserProfile.PrivShares)
	if priv == nil {
		log.Error("No valid private share")
		return
	}

	for {
		time.Sleep(time.Second * 1)
		identity.ScanIdentityAccount(usechain, priv, CommitteeNodeList)
	}
}

//The verifier collect the shares, and verify the account
func AccountShareVerifer(usechain *config.Usechain) {
	for {
		time.Sleep(time.Second * 5)
		CheckVerifyMsg(usechain, CommitteeRequires)
	}
}
