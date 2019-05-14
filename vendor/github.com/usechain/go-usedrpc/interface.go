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
	"math/big"
)

type UsechainAPI interface {
	Web3ClientVersion() (string, error)
	Web3Sha3(data []byte) (string, error)
	NetVersion() (string, error)
	NetListening() (bool, error)
	NetPeerCount() (int, error)
	UseProtocolVersion() (string, error)
	UseSyncing() (*Syncing, error)
	UseCoinbase() (string, error)
	UseMining() (bool, error)
	UseHashrate() (int, error)
	UseGasPrice() (big.Int, error)
	UseAccounts() ([]string, error)
	UseBlockNumber() (int, error)
	UseGetBalance(address, block string) (big.Int, error)
	UseGetStorageAt(data string, position int, tag string) (string, error)
	UseGetTransactionCount(address, block string) (int, error)
	UseGetBlockTransactionCountByHash(hash string) (int, error)
	UseGetBlockTransactionCountByNumber(number int) (int, error)
	UseGetUncleCountByBlockHash(hash string) (int, error)
	UseGetUncleCountByBlockNumber(number int) (int, error)
	UseGetCode(address, block string) (string, error)
	UseSign(address, data string) (string, error)
	UseSendTransaction(transaction T) (string, error)
	UseSendRawTransaction(data string) (string, error)
	UseCall(transaction T, tag string) (string, error)
	UseEstimateGas(transaction T) (int, error)
	UseGetBlockByHash(hash string, withTransactions bool) (*Block, error)
	UseGetBlockByNumber(number int, withTransactions bool) (*Block, error)
	UseGetTransactionByHash(hash string) (*Transaction, error)
	UseGetTransactionByBlockHashAndIndex(blockHash string, transactionIndex int) (*Transaction, error)
	UseGetTransactionByBlockNumberAndIndex(blockNumber, transactionIndex int) (*Transaction, error)
	UseGetTransactionReceipt(hash string) (*TransactionReceipt, error)
	UseGetCompilers() ([]string, error)
	UseNewFilter(params FilterParams) (string, error)
	UseNewBlockFilter() (string, error)
	UseNewPendingTransactionFilter() (string, error)
	UseUninstallFilter(filterID string) (bool, error)
	UseGetFilterChanges(filterID string) ([]Log, error)
	UseGetFilterLogs(filterID string) ([]Log, error)
	UseGetLogs(params FilterParams) ([]Log, error)
}

var _ UsechainAPI = (*UseRPC)(nil)
