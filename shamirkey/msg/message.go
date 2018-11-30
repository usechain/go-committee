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

package msg

import (
	"fmt"
	"time"
	"math/big"
	"encoding/json"
	"crypto/ecdsa"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/utils"
)

//The committee message type
type MsgType int

//Enumrator of message type
const (
	PolynomialShare MsgType = iota    // value --> 0  PolynomialShares
	Keyshare						  // value --> 1  Keyshare
	SubAccountVerifyMsg				  // value --> 2  SubAccount verify message
	NewCommitteeLogInMsg 			  // value --> 3  New committee connected the network, request for shares
	Unknown
)

//The struct of the committee message
type Msg struct {
	ID 			int 		`json:"ID"`
	Sender		int			`json:"Sender"`
	Type 	    MsgType		`json:"MsgType"`
	Data 		[][]byte	`json:"Data"`
}

//Unmarshal the message
func UnpackMsg(b []byte) (*Msg, error) {
	m := Msg{}

	err := json.Unmarshal(b, &m)
	if err != nil{
		log.Debug("Unmarshal failed")
		return nil,err
	}

	return  &m, nil
}

//Pack the polynomialShare message
func PackPolynomialShare(polys []*ecdsa.PublicKey, id int) []byte{
	d := make([][]byte, len(polys))
	for i := range polys {
		fmt.Println("public key", polys[i])
		d[i] = crypto.FromECDSAPub(polys[i])
	}

	msg := 	Msg {
		ID: time.Now().Nanosecond(),
		Sender: id,
		Type: PolynomialShare,
		Data: d,
	}
	m, _ := json.Marshal(msg)

	return m
}

//Unpack the polynomialShare payload
func UnpackPolynomialShare(datas [][]byte) []*ecdsa.PublicKey {
	p := make([]*ecdsa.PublicKey, len(datas))

	for i := range datas {
		p[i] = crypto.ToECDSAPub(datas[i])
		fmt.Println("receive", *p[i])
	}
	return p
}

//Pack the SubAccountVerifyMsg message
func PackAccountVerifyShare(certid *big.Int, pubs []*ecdsa.PublicKey, pubSkey string, priv *ecdsa.PrivateKey, id int) []byte{
	var pubShares []string = make([]string, len(pubs))
	var bA = new(ecdsa.PublicKey)

	for i, pub := range pubs {
		bA.X, bA.Y = crypto.S256().ScalarMult(pub.X, pub.Y, priv.D.Bytes())

		pubShares[i] += utils.ToBase64(big.NewInt(int64(id+1)))
		pubShares[i] += utils.ToBase64(bA.X)
		pubShares[i] += utils.ToBase64(bA.Y)
	}

	fmt.Println(pubShares)

	d := make([][]byte, len(pubs) + 1)
	for i := 0; i < len(pubs) + 1; i++ {
		switch i {
		case 0:
			d[i] = certid.Bytes()
			continue
		case 1:
			d[i] = []byte(pubSkey)
			continue
		default:
			d[i] = []byte(pubShares[i-2])
		}
	}

	msg := 	Msg {
		ID: time.Now().Nanosecond(),
		Sender: id,
		Type: SubAccountVerifyMsg,
		Data: d,
	}
	b, _ := json.Marshal(msg)

	return b
}

//Unpack the SubAccountVerifyMsg message's payload
func UnpackAccountVerifyShare(datas [][]byte) (*big.Int, []string, string) {
	var certID *big.Int
	var pubSkey string
	var pubshares = make([]string, len(datas) - 1 )

	for i := range datas {
		switch i {
		case 0:
			certID = big.NewInt(0).SetBytes(datas[i])
			continue
		case 1:
			pubSkey = string(datas[i])
			continue
		default:
			pubshares[i-2] = string(datas[i])
		}
	}
	return certID, pubshares, pubSkey
}

//Pack the keyPointShare message
func PackKeyPointShare(p string, id int) []byte{
	d := make([][]byte, 1)
	d[0] = []byte(p)

	msg := 	Msg {
		ID: time.Now().Nanosecond(),
		Sender: id,
		Type: Keyshare,
		Data: d,
	}
	b, _ := json.Marshal(msg)

	return b
}

//Pack the NewCommitteeLogInMsg
func PackCommitteeNewLogin(id int) []byte{
	msg := 	Msg {
		ID: time.Now().Nanosecond(),
		Sender: id,
		Type: NewCommitteeLogInMsg,
		Data: [][]byte{},
	}
	b, _ := json.Marshal(msg)

	return b
}
