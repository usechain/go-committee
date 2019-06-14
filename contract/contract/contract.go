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



const CreditAddr = "0xc852139d19a459da52cC9F6905F239321d0b5aa6"
const CreditABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"_publicKey\",\"type\":\"string\"},{\"name\":\"_hashKey\",\"type\":\"bytes32\"},{\"name\":\"_identity\",\"type\":\"bytes\"},{\"name\":\"_issuer\",\"type\":\"bytes\"},{\"name\":\"_ciphertext\",\"type\":\"bool\"}],\"name\":\"register\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_pubkey\",\"type\":\"string\"},{\"name\":\"_encryptedAS\",\"type\":\"string\"},{\"name\":\"_ciphertext\",\"type\":\"bool\"}],\"name\":\"subRegister\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_registerID\",\"type\":\"uint256\"},{\"name\":\"_hashKey\",\"type\":\"bytes32\"},{\"name\":\"_status\",\"type\":\"uint256\"},{\"name\":\"_verifiedAddr\",\"type\":\"address\"}],\"name\":\"verifyHash\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_registerID\",\"type\":\"uint256\"},{\"name\":\"_status\",\"type\":\"uint256\"}],\"name\":\"verifySub\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"CommitteeAddr\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"confirmedMainAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"confirmedMainAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"confirmedSubAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"confirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"getAccountStatus\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnConfirmedMainAddrLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnConfirmedSubAddrLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnEncryptedSubAddrLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"HashKeyToAddr\",\"outputs\":[{\"name\":\"toAddress\",\"type\":\"address\"},{\"name\":\"status\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"isMainAccount\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"MainAccount\",\"outputs\":[{\"name\":\"addr\",\"type\":\"address\"},{\"name\":\"hashKey\",\"type\":\"bytes32\"},{\"name\":\"status\",\"type\":\"uint256\"},{\"name\":\"identity\",\"type\":\"bytes\"},{\"name\":\"issuer\",\"type\":\"bytes\"},{\"name\":\"publicKey\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"queryAddrState\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"RegisterID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"RegisterIDtoAddr\",\"outputs\":[{\"name\":\"verified\",\"type\":\"bool\"},{\"name\":\"toAddress\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"SubAccount\",\"outputs\":[{\"name\":\"addr\",\"type\":\"address\"},{\"name\":\"status\",\"type\":\"uint256\"},{\"name\":\"publicKey\",\"type\":\"string\"},{\"name\":\"encryptedAS\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_user\",\"type\":\"address\"}],\"name\":\"test\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"unConfirmedMainAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"UnConfirmedMainAddrID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"unConfirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"UnConfirmedSubAddrID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"unEncryptedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"UnEncryptedSubAddrID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"


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

	coinbaseUM := common.AddressToBase58Address(common.HexToAddress(coinbase)).String()
	ctrUM := common.AddressToBase58Address(common.HexToAddress(crt.Address)).String()

	tx := usedrpc.T {
		From:  coinbaseUM,
		To:    ctrUM,
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
		log.Debug("unpack abi failed:", err)
		return nil, err
	}

	return OutDataInterface, nil
}

var Nonce uint64

func (crt *Contract) ContractTransaction(node *usedrpc.UseRPC, ks *keystore.KeyStore, coinbase string, method string, params ...interface{}) (string, error) {
	bytes, err := crt.Abi.Pack(method, params ...)
	if err != nil {
		return "", err
	}
	//coinbaseUM := common.AddressToBase58Address(common.HexToAddress(coinbase)).String()
	//xAddr := common.UmAddressToAddress(coinbase)
	//nonce, err := node.UseGetTransactionCount(common.ToHex(xAddr[:]), "latest")
	nonce, err := node.UseGetTransactionCount(coinbase, "latest")
	log.Info("nonce(latest)", "nonce", nonce)
	if err != nil {
		log.Error("Get nonce failed", "error", err)
	}

	if Nonce <= uint64(nonce) {
		Nonce = uint64(nonce)
	}

	tx := types.NewTransaction(Nonce, common.HexToAddress(crt.Address), nil, 10000000, big.NewInt(20000000000), bytes)
	ac, err := account.CommitteeAccount(common.UmAddressToAddress(coinbase), ks)
	if err != nil {
		log.Error("account:", "err", err)
	}

	// TODO NETWORK id
	signedTx, err := ks.SignTx(ac, tx, big.NewInt(1))

	if err != nil {
		log.Error("Sign the committee Msg failed, Please unlock the verifier account", "err", err)
		return "", err
	}
	txbyte, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		log.Error("rlp ecode error", "err" , err)
	}
	result, err := node.UseSendRawTransaction(hexutil.Encode(txbyte))
	Nonce++
	return result, err
}
