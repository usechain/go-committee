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
	"math/big"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-committee/shamirkey/core"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/shamirkey/msg"
	"github.com/usechain/go-committee/shamirkey/verify"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/contract/creditNew"
	"sort"
)

//Read committee config from contract
func InitShamirCommitteeNumber(config config.Usechain) {
	rpc := config.NodeRPC
	ctr := config.ManagerContract
	coinbase := config.UserProfile.Address

	//Check whether a real committee
	MAX_COMMITTEEMAN_COUNT, err := ctr.ContractCallParsed(rpc, coinbase, "MAX_COMMITTEEMAN_COUNT")
	fmt.Println("MAX_COMMITTEEMAN_COUNT", MAX_COMMITTEEMAN_COUNT)
	if err != nil {
		fmt.Println("read MAX_COMMITTEEMAN_COUNT failed",  err)
		return
	}
	max, ok := (MAX_COMMITTEEMAN_COUNT[0]).(*big.Int)
	if !ok {
		log.Error("It's not ok for", "type", reflect.TypeOf(MAX_COMMITTEEMAN_COUNT[0]))
		return
	}

	//Check whether a real committee
	Requirement, err := ctr.ContractCallParsed(rpc, coinbase, "Requirement")
	if err != nil {
		fmt.Println("read Requirement failed",  err)
		return
	}
	min, ok := (Requirement[0]).(*big.Int)
	if !ok {
		log.Error("It's not ok for", "type", reflect.TypeOf(Requirement[0]))
		return
	}

	core.CommitteeMax = int(max.Int64())
	core.CommitteeRequires = int(min.Int64())

	for i := 0; i < core.CommitteeMax; i++ {
		//Get committee asym key
		getCommitteeAsymkey, err := ctr.ContractCallParsed(rpc, coinbase, "getCommitteeAsymkey", big.NewInt(int64(i)))
		if err != nil {
			fmt.Println("read committee failed",  err)
			return
		}
		asym, ok := (getCommitteeAsymkey[0]).(string)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(getCommitteeAsymkey[0]))
			return
		}
		// Prevent duplicate additions
		core.CommitteeNodeList = append(core.CommitteeNodeList, asym)
	}
	core.CommitteeNodeList = RemoveDuplicate(core.CommitteeNodeList)
	log.Debug("CommitteeNodeList", "list", core.CommitteeNodeList)
}

func ShamirKeySharesGenerate(id int, keypool *core.KeyPool) {
	// committee generate a random number, di
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Crit(fmt.Sprintf("Failed to generate ephemeral node key: %v", err))
	}
	fmt.Println("******priv******", priv.D)

	// generate shares
	created, _, polynomials, err := sssa.Create256Bit(core.CommitteeRequires, core.CommitteeMax, priv.D)
	if err != nil {
		log.Error("err", err)
		return
	}
	combined, err := sssa.Combine256Bit(created)
	if err != nil || combined.Cmp(priv.D) != 0 {
		log.Error("Fatal: combining: ", err)
		return
	}

	polyPublicKeys := sssa.ToECDSAPubArray(polynomials)

	if !sssa.VerifyCreatedAndPolynomial(created, polyPublicKeys) {
		log.Error("Fatal: verifying: ", err)
		return
	}

	// broadcast the shares
	m := msg.PackPolynomialShare(polyPublicKeys, id)
	wnode.SendMsg(m, nil)

	keypool.InsertKeyCache(string(m))

	// send f(j) to j committee
	for i:= range core.CommitteeNodeList {
		m = msg.PackKeyPointShare(created[i], id)
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(core.CommitteeNodeList[i])))
		keypool.InsertKeyCache(string(m))
	}
}

// Broadcast polynomialShare && send f(j) to determined committee
func ShamirSharesReponse(requester int, keypool *core.KeyPool) {
	if keypool.Cachelen() > requester + 1 {
		wnode.SendMsg([]byte(keypool.KeyCache(0)), nil)
		wnode.SendMsg([]byte(keypool.KeyCache(requester+1)), crypto.ToECDSAPub(common.FromHex(core.CommitteeNodeList[requester])))
	}
}

// Broadcast NewCommitteeLogInMsg,  request for sharing keys
func SendRequestShares(senderid int) {
	m := msg.PackCommitteeNewLogin(senderid)
	wnode.SendMsg(m, nil)
}

// Listening the network msg
func ShamirKeySharesListening(p *config.CommittteeProfile, pool *core.SharePool, keypool *core.KeyPool) {
	log.Debug("Listening...")
	var input []byte

	for {
		input = <-wnode.ChanWhisper

		m, err := msg.UnpackMsg(input)
		if err != nil {
			fmt.Println("Unknown msg type: ", err)
			continue
		}

		switch m.Type {
		case msg.PolynomialShare:
			log.Debug("received polynomial shares")
			keypool.InsertPolynomialShare(m.Sender, msg.UnpackPolynomialShare(m.Data))
		case msg.Keyshare:
			log.Debug("received key shares")
			keypool.InsertPrivateKeyShare(m.Sender, string(m.Data[0]))
		case msg.NewCommitteeLogInMsg:
			log.Debug("detected a new logged in committee")
			ShamirSharesReponse(m.Sender, keypool)
		case msg.VerifyShareMsg:
			A, bsA := msg.UnpackVerifyShare(m.Data)
			log.Debug("received a new shared for account verifying")
			if verify.IsAccountVerifier(A, core.CommitteeMax, p.CommitteeID) {
				pool.SaveAccountSharedCache(A, bsA, m.Sender)
			}
		}
	}
}

// The process for account verify, read the manage contract and handle un-register request
func AccountVerifyProcess(usechain *config.Usechain, pool *core.SharePool) {

	go func() {
		pool.CheckSharedMsg(usechain, core.CommitteeRequires)
	}()

	select {
	case v := <- pool.VerifiedChan:
		pubkey := crypto.ToECDSAPub(common.FromHex(v))
		fmt.Println("VerifiedChan pubkey", pubkey)

		addr := crypto.PubkeyToAddress(*pubkey)
		certHash := pool.GetVerifiedCertHash(v)

		creditNew.ConfirmCreditSystemAccount(usechain, addr, certHash)
		fmt.Println("send success")

	}
}

func RemoveDuplicate(a []string) (ret []string) {
	sort.Strings(a)
	if reflect.TypeOf(a).Kind() != reflect.Slice {
		fmt.Printf("<SliceRemoveDuplicate> <a> is not slice but %T\n", a)
		return ret
	}

	va := reflect.ValueOf(a)
	for i := 0; i < va.Len(); i++ {
		if i > 0 && reflect.DeepEqual(va.Index(i-1).Interface(), va.Index(i).Interface()) {
			continue
		}
		ret = append(ret, va.Index(i).Interface().(string))
	}
	return ret
}