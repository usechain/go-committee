// Copyright 2018 The go-usedrpc Authors
// This file is part of the go-usedrpc library.
//
// The go-usedrpc library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usedrpc library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usedrpc library. If not, see <http://www.gnu.org/licenses/>.

package usedrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
)

// UseError - used error
type UseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (err UseError) Error() string {
	return fmt.Sprintf("Error %d (%s)", err.Code, err.Message)
}

type useResponse struct {
	ID      int             `json:"id"`
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *UseError       `json:"error"`
}

type useRequest struct {
	ID      int           `json:"id"`
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// UseRPC - Usechain rpc client
type UseRPC struct {
	url    string
	client httpClient
	log    logger
	Debug  bool
}

// New create new rpc client with given url
func New(url string, options ...func(rpc *UseRPC)) *UseRPC {
	rpc := &UseRPC{
		url:    url,
		client: http.DefaultClient,
		log:    log.New(os.Stderr, "", log.LstdFlags),
		Debug:  false,
	}
	for _, option := range options {
		option(rpc)
	}

	return rpc
}

// NewUseRPC create new rpc client with given url
func NewUseRPC(url string, options ...func(rpc *UseRPC)) *UseRPC {
	return New(url, options...)
}

func (rpc *UseRPC) call(method string, target interface{}, params ...interface{}) error {
	result, err := rpc.Call(method, params...)
	if err != nil {
		return err
	}

	if target == nil {
		return nil
	}

	return json.Unmarshal(result, target)
}

// URL returns client url
func (rpc *UseRPC) URL() string {
	return rpc.url
}

// Call returns raw response of method call
func (rpc *UseRPC) Call(method string, params ...interface{}) (json.RawMessage, error) {
	request := useRequest{
		ID:      1,
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := rpc.client.Post(rpc.url, "application/json", bytes.NewBuffer(body))
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if rpc.Debug {
		rpc.log.Println(fmt.Sprintf("%s\nRequest: %s\nResponse: %s\n", method, body, data))
	}

	resp := new(useResponse)
	if err := json.Unmarshal(data, resp); err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, *resp.Error
	}

	return resp.Result, nil

}

// RawCall returns raw response of method call (Deprecated)
func (rpc *UseRPC) RawCall(method string, params ...interface{}) (json.RawMessage, error) {
	return rpc.Call(method, params...)
}

// Web3ClientVersion returns the current client version.
func (rpc *UseRPC) Web3ClientVersion() (string, error) {
	var clientVersion string

	err := rpc.call("web3_clientVersion", &clientVersion)
	return clientVersion, err
}

// Web3Sha3 returns Keccak-256 (not the standardized SHA3-256) of the given data.
func (rpc *UseRPC) Web3Sha3(data []byte) (string, error) {
	var hash string

	err := rpc.call("web3_sha3", &hash, fmt.Sprintf("0x%x", data))
	return hash, err
}

// NetVersion returns the current network protocol version.
func (rpc *UseRPC) NetVersion() (string, error) {
	var version string

	err := rpc.call("net_version", &version)
	return version, err
}

// NetListening returns true if client is actively listening for network connections.
func (rpc *UseRPC) NetListening() (bool, error) {
	var listening bool

	err := rpc.call("net_listening", &listening)
	return listening, err
}

// NetPeerCount returns number of peers currently connected to the client.
func (rpc *UseRPC) NetPeerCount() (int, error) {
	var response string
	if err := rpc.call("net_peerCount", &response); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseQueryAddress returns the authentication state of the address
func (rpc *UseRPC) UseQueryAddress(address, block string) (bool, error) {
	var response int
	err := rpc.call("eth_queryAddr", &response, address, block)
	return response == 1, err
}

// UseIsMiner returns true if the coinbase is a miner
func (rpc *UseRPC) UseIsMiner(address, block string) (bool, error) {
	var response int
	err := rpc.call("eth_isMiner", &response, address, block)
	return response == 1, err
}

// UseIsPunishedMiner returns true if the coinbase is a punished miner
func (rpc *UseRPC) UseIsPunishedMiner(address, block string) (bool, error) {
	var response int
	err := rpc.call("eth_isPunishedMiner", &response, address, block)
	return response == 1, err
}

func (rpc *UseRPC) UnlockAccount(address, pass string) (bool, error) {
	var res bool
	err := rpc.call("personal_unlockAccount", &res, address, pass, 0)
	return res, err
}

func (rpc *UseRPC) MinerStart() (error) {
	var res interface{}
	err := rpc.call("miner_start", &res, 0)
	return  err
}

func (rpc *UseRPC) GetCertifications(address string) (interface{}, error) {
	var res interface{}
	err := rpc.call("eth_getCertifications", &res, address , "latest")
	return res, err
}


// UseMinerRegister send a transaction to minerList contract to get registered.
// The param "to" & "data" in tx are useless
func (rpc *UseRPC) UseMinerRegister(transaction T) (string, error) {
	var hash string
	err := rpc.call("eth_sendTransaction", &hash, transaction)
	return hash, err
}

// UseMinerUnRegister send a transaction to minerList contract to get unregistered.
// The param "to" & "data" in tx are useless
func (rpc *UseRPC) UseMinerUnRegister(transaction T) (string, error) {
	var hash string
	err := rpc.call("eth_sendTransaction", &hash, transaction)
	return hash, err
}

// UseSendOneTimeTransaction for the OTA authentication, send Tx with personal
// certificate & key signature
func (rpc *UseRPC) UseSendOneTimeTransaction(transaction T) (string, error) {
	var hash string
	err := rpc.call("eth_sendOneTimeTransaction", &hash, transaction)
	return hash, err
}

// UseSendMainTransaction for the main account authentication, send Tx with OTA ringSig
func (rpc *UseRPC) UseSendMainTransaction(transaction T, parent string, state string) (string, error) {
	var hash string
	err := rpc.call("eth_sendMainTransaction", &hash,  parent, transaction, state)
	return hash, err
}

// UseSendSubTransaction for the sub account authentication, send Tx with any verified account ringsig
func (rpc *UseRPC) UseSendSubTransaction(transaction T, parent string, state string) (string, error) {
	var hash string
	err := rpc.call("eth_sendSubTransaction", &hash,  parent, transaction, state)
	return hash, err
}

// UseProtocolVersion returns the current used protocol version.
func (rpc *UseRPC) UseProtocolVersion() (string, error) {
	var protocolVersion string

	err := rpc.call("eth_protocolVersion", &protocolVersion)
	return protocolVersion, err
}

// UseSyncing returns an object with data about the sync status or false.
func (rpc *UseRPC) UseSyncing() (*Syncing, error) {
	result, err := rpc.RawCall("eth_syncing")
	if err != nil {
		return nil, err
	}
	syncing := new(Syncing)
	if bytes.Equal(result, []byte("false")) {
		return syncing, nil
	}
	err = json.Unmarshal(result, syncing)
	return syncing, err
}

// UseCoinbase returns the client coinbase address
func (rpc *UseRPC) UseCoinbase() (string, error) {
	var address string

	err := rpc.call("eth_coinbase", &address)
	return address, err
}

// UseMining returns true if client is actively mining new blocks.
func (rpc *UseRPC) UseMining() (bool, error) {
	var mining bool

	err := rpc.call("eth_mining", &mining)
	return mining, err
}

// UseHashrate returns the number of hashes per second that the node is mining with.
func (rpc *UseRPC) UseHashrate() (int, error) {
	var response string

	if err := rpc.call("eth_hashrate", &response); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGasPrice returns the current price per gas in wei.
func (rpc *UseRPC) UseGasPrice() (big.Int, error) {
	var response string
	if err := rpc.call("eth_gasPrice", &response); err != nil {
		return big.Int{}, err
	}

	return ParseBigInt(response)
}

// UseAccounts returns a list of addresses owned by client.
func (rpc *UseRPC) UseAccounts() ([]string, error) {
	accounts := []string{}

	err := rpc.call("eth_accounts", &accounts)
	return accounts, err
}

// UseBlockNumber returns the number of most recent block.
func (rpc *UseRPC) UseBlockNumber() (int, error) {
	var response string
	if err := rpc.call("eth_blockNumber", &response); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGetBalance returns the balance of the account of given address in wei.
func (rpc *UseRPC) UseGetBalance(address, block string) (big.Int, error) {
	var response string
	if err := rpc.call("eth_getBalance", &response, address, block); err != nil {
		return big.Int{}, err
	}

	return ParseBigInt(response)
}

// UseGetStorageAt returns the value from a storage position at a given address.
func (rpc *UseRPC) UseGetStorageAt(data string, position int, tag string) (string, error) {
	var result string

	err := rpc.call("eth_getStorageAt", &result, data, IntToHex(position), tag)
	return result, err
}

// UseGetTransactionCount returns the number of transactions sent from an address.
func (rpc *UseRPC) UseGetTransactionCount(address, block string) (int, error) {
	var response string

	if err := rpc.call("eth_getTransactionCount", &response, address, block); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGetBlockTransactionCountByHash returns the number of transactions in a block from a block matching the given block hash.
func (rpc *UseRPC) UseGetBlockTransactionCountByHash(hash string) (int, error) {
	var response string

	if err := rpc.call("eth_getBlockTransactionCountByHash", &response, hash); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGetBlockTransactionCountByNumber returns the number of transactions in a block from a block matching the given block
func (rpc *UseRPC) UseGetBlockTransactionCountByNumber(number int) (int, error) {
	var response string

	if err := rpc.call("eth_getBlockTransactionCountByNumber", &response, IntToHex(number)); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGetUncleCountByBlockHash returns the number of uncles in a block from a block matching the given block hash.
func (rpc *UseRPC) UseGetUncleCountByBlockHash(hash string) (int, error) {
	var response string

	if err := rpc.call("eth_getUncleCountByBlockHash", &response, hash); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGetUncleCountByBlockNumber returns the number of uncles in a block from a block matching the given block number.
func (rpc *UseRPC) UseGetUncleCountByBlockNumber(number int) (int, error) {
	var response string

	if err := rpc.call("eth_getUncleCountByBlockNumber", &response, IntToHex(number)); err != nil {
		return 0, err
	}

	return ParseInt(response)
}

// UseGetCode returns code at a given address.
func (rpc *UseRPC) UseGetCode(address, block string) (string, error) {
	var code string

	err := rpc.call("eth_getCode", &code, address, block)
	return code, err
}

// UseSign signs data with a given address.
// Calculates an Usechain specific signature with: sign(keccak256("\x19Usechain Signed Message:\n" + len(message) + message)))
func (rpc *UseRPC) UseSign(address, data string) (string, error) {
	var signature string

	err := rpc.call("eth_sign", &signature, address, data)
	return signature, err
}

// UseSendTransaction creates new message call transaction or a contract creation, if the data field contains code.
func (rpc *UseRPC) UseSendTransaction(transaction T) (string, error) {
	var hash string

	err := rpc.call("eth_sendTransaction", &hash, transaction)
	return hash, err
}

func (rpc *UseRPC) SendCreditRegisterTransaction(transaction T, enc bool) (string, error) {
	var hash string

	err := rpc.call("eth_sendCreditRegisterTransaction", &hash, transaction, enc)
	return hash, err
}

// UseSendRawTransaction creates new message call transaction or a contract creation for signed transactions.
func (rpc *UseRPC) UseSendRawTransaction(data string) (string, error) {
	var hash string

	err := rpc.call("eth_sendRawTransaction", &hash, data)
	return hash, err
}

// UseCall executes a new message call immediately without creating a transaction on the block chain.
func (rpc *UseRPC) UseCall(transaction T, tag string) (string, error) {
	var data string

	err := rpc.call("eth_call", &data, transaction, tag)
	return data, err
}

// UseEstimateGas makes a call or transaction, which won't be added to the blockchain and returns the used gas, which can be used for estimating the used gas.
func (rpc *UseRPC) UseEstimateGas(transaction T) (int, error) {
	var response string

	err := rpc.call("eth_estimateGas", &response, transaction)
	if err != nil {
		return 0, err
	}

	return ParseInt(response)
}

func (rpc *UseRPC) getBlock(method string, withTransactions bool, params ...interface{}) (*Block, error) {
	result, err := rpc.RawCall(method, params...)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(result, []byte("null")) {
		return nil, nil
	}

	var response proxyBlock
	if withTransactions {
		response = new(proxyBlockWithTransactions)
	} else {
		response = new(proxyBlockWithoutTransactions)
	}

	err = json.Unmarshal(result, response)
	if err != nil {
		return nil, err
	}

	block := response.toBlock()
	return &block, nil
}

// UseGetBlockByHash returns information about a block by hash.
func (rpc *UseRPC) UseGetBlockByHash(hash string, withTransactions bool) (*Block, error) {
	return rpc.getBlock("eth_getBlockByHash", withTransactions, hash, withTransactions)
}

// UseGetBlockByNumber returns information about a block by block number.
func (rpc *UseRPC) UseGetBlockByNumber(number int, withTransactions bool) (*Block, error) {
	return rpc.getBlock("eth_getBlockByNumber", withTransactions, IntToHex(number), withTransactions)
}

func (rpc *UseRPC) getTransaction(method string, params ...interface{}) (*Transaction, error) {
	transaction := new(Transaction)

	err := rpc.call(method, transaction, params...)
	return transaction, err
}

// UseGetTransactionByHash returns the information about a transaction requested by transaction hash.
func (rpc *UseRPC) UseGetTransactionByHash(hash string) (*Transaction, error) {
	return rpc.getTransaction("eth_getTransactionByHash", hash)
}

// UseGetTransactionByBlockHashAndIndex returns information about a transaction by block hash and transaction index position.
func (rpc *UseRPC) UseGetTransactionByBlockHashAndIndex(blockHash string, transactionIndex int) (*Transaction, error) {
	return rpc.getTransaction("eth_getTransactionByBlockHashAndIndex", blockHash, IntToHex(transactionIndex))
}

// UseGetTransactionByBlockNumberAndIndex returns information about a transaction by block number and transaction index position.
func (rpc *UseRPC) UseGetTransactionByBlockNumberAndIndex(blockNumber, transactionIndex int) (*Transaction, error) {
	return rpc.getTransaction("eth_getTransactionByBlockNumberAndIndex", IntToHex(blockNumber), IntToHex(transactionIndex))
}

// UseGetTransactionReceipt returns the receipt of a transaction by transaction hash.
// Note That the receipt is not available for pending transactions.
func (rpc *UseRPC) UseGetTransactionReceipt(hash string) (*TransactionReceipt, error) {
	transactionReceipt := new(TransactionReceipt)

	err := rpc.call("eth_getTransactionReceipt", transactionReceipt, hash)
	if err != nil {
		return nil, err
	}

	return transactionReceipt, nil
}

// UseGetCompilers returns a list of available compilers in the client.
func (rpc *UseRPC) UseGetCompilers() ([]string, error) {
	compilers := []string{}

	err := rpc.call("eth_getCompilers", &compilers)
	return compilers, err
}

// UseNewFilter creates a new filter object.
func (rpc *UseRPC) UseNewFilter(params FilterParams) (string, error) {
	var filterID string
	err := rpc.call("eth_newFilter", &filterID, params)
	return filterID, err
}

// UseNewBlockFilter creates a filter in the node, to notify when a new block arrives.
// To check if the state has changed, call UseGetFilterChanges.
func (rpc *UseRPC) UseNewBlockFilter() (string, error) {
	var filterID string
	err := rpc.call("eth_newBlockFilter", &filterID)
	return filterID, err
}

// UseNewPendingTransactionFilter creates a filter in the node, to notify when new pending transactions arrive.
// To check if the state has changed, call UseGetFilterChanges.
func (rpc *UseRPC) UseNewPendingTransactionFilter() (string, error) {
	var filterID string
	err := rpc.call("eth_newPendingTransactionFilter", &filterID)
	return filterID, err
}

// UseUninstallFilter uninstalls a filter with given id.
func (rpc *UseRPC) UseUninstallFilter(filterID string) (bool, error) {
	var res bool
	err := rpc.call("eth_uninstallFilter", &res, filterID)
	return res, err
}

// UseGetFilterChanges polling method for a filter, which returns an array of logs which occurred since last poll.
func (rpc *UseRPC) UseGetFilterChanges(filterID string) ([]Log, error) {
	var logs = []Log{}
	err := rpc.call("eth_getFilterChanges", &logs, filterID)
	return logs, err
}

// UseGetFilterLogs returns an array of all logs matching filter with given id.
func (rpc *UseRPC) UseGetFilterLogs(filterID string) ([]Log, error) {
	var logs = []Log{}
	err := rpc.call("eth_getFilterLogs", &logs, filterID)
	return logs, err
}

// UseGetLogs returns an array of all logs matching a given filter object.
func (rpc *UseRPC) UseGetLogs(params FilterParams) ([]Log, error) {
	var logs = []Log{}
	err := rpc.call("eth_getLogs", &logs, params)
	return logs, err
}

// Use1 returns 1 used value (10^18 Hui)
func (rpc *UseRPC) Use1() *big.Int {
	return Use1()
}

// Use1 returns 1 used value (10^18 Hui)
func Use1() *big.Int {
	return big.NewInt(1000000000000000000)
}
