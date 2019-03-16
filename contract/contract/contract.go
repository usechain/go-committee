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

package contract

import (
	"strings"
	"github.com/usechain/go-usechain/accounts/abi"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usedrpc"
	"github.com/usechain/go-committee/account"
	"math/big"
	"fmt"
	"encoding/hex"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"

	"github.com/usechain/go-usechain/rlp"
)


// Structure of a contract
type Contract struct {
	Name        string
	Description string
	Address   	string
	Abi         abi.ABI
}

const (
	ContractFalse = "0x0000000000000000000000000000000000000000000000000000000000000000"
	ContractTrue  = "0x0000000000000000000000000000000000000000000000000000000000000001"
	ContractZero  = "0x0000000000000000000000000000000000000000000000000000000000000000"
	ContractOne   = "0x0000000000000000000000000000000000000000000000000000000000000001"
	ContractNull  = "0x"
)

// New create new contract client
func New(name string,  description string, address string, abistr string) (*Contract, error) {
	a, err := abi.JSON(strings.NewReader(abistr))
	if err != nil {
		return nil, err
	}

	contract := &Contract{
		Name:			name,
		Description:	description,
		Address:    	address,
		Abi:			a,
	}

	return contract, nil
}


// Call returns raw response of method call
func (crt *Contract) Call(method string, params ...interface{}) []byte {
	bytesData, _ := crt.Abi.Pack(method, params)
	return bytesData
}

// Call returns raw response of method call, based on rpc call
func (crt *Contract) ContractCall(node *usedrpc.UseRPC, coinbase string, method string, params ...interface{}) (string, error) {
	bytes, err := crt.Abi.Pack(method, params ...)
	if err != nil {

		return "", err
	}

	tx := usedrpc.T {
		From:  coinbase,
		To:    crt.Address,
		Value: big.NewInt(0),
		Data:  hexutil.Encode(bytes),
	}

	result, err := node.UseCall(tx, "latest")
	return result, err
}

//Call returns parsed response of method call, based on rpc call
func (crt *Contract) ContractCallParsed(rpc *usedrpc.UseRPC, coinbase string, methodname string, params ...interface{}) ([]interface{}, error) {
	res, err := crt.ContractCall(rpc, coinbase, methodname, params...)
	if err != nil {
		return nil, err
	}

	method, exist := crt.Abi.Methods[methodname]
	if !exist {
		return nil, fmt.Errorf("method '%s' not found", methodname)
	}
	decodeData, err := hex.DecodeString(res[2:])
	OutDataInterface,err :=method.Outputs.UnpackABI(decodeData)
	if err != nil {
		fmt.Println("unpack abi failed:", err)
		return nil, err
	}

	return OutDataInterface, nil
}

func (crt *Contract) ContractTransaction(node *usedrpc.UseRPC, ks *keystore.KeyStore, coinbase string, method string, params ...interface{}) (string, error) {
	bytes, err := crt.Abi.Pack(method, params ...)
	if err != nil {
		return "", err
	}

	nonce, err := node.UseGetTransactionCount(coinbase, "latest")
	if err != nil {
		log.Error("Get nonce failed", "error", err)
	}

	//fmt.Printf("bytes: %x\n", bytes)
	tx := types.NewTransaction(uint64(nonce), common.HexToAddress(crt.Address), nil, 1000000, big.NewInt(2000000000), bytes)
	//fmt.Println("coinbase", coinbase)
	//ks := account.DefaultKeystore()
	ac, err := account.CommitteeAccount(common.HexToAddress(coinbase), ks)
	if err != nil {
		fmt.Println("account:", err)
	}
	//fmt.Println("ac",ac.Address.Hex())

	signedTx, err := ks.SignTx(ac, tx, big.NewInt(2))
	if err != nil {
		log.Error("Sign the committee Msg failed, Please unlock the verifier account", "err", err)
		return "", err
	}
	//fmt.Println("signed")

	txbyte, err := rlp.EncodeToBytes(signedTx)
	result, err := node.UseSendRawTransaction(hexutil.Encode(txbyte))
	return result, err
}
