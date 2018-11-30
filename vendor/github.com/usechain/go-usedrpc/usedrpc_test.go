package usedrpc

import (
	"fmt"
	"testing"
	"math/big"
)

func TestRPCClient(t *testing.T) {
	c := NewUseRPC("http://127.0.0.1:8545")
	coinbase, err := c.UseCoinbase()
	fmt.Println("The block number:", err, coinbase)
}

func TestRPCQueryAddress(t *testing.T) {
	c := NewUseRPC("http://127.0.0.1:8545")
	flag, err := c.UseQueryAddress("0x6da8c30181d22e69fb17fa498f5cba5b09ecd572", "latest")
	fmt.Println("The address auentication stat is", err, flag)
}

func TestRPCMiner(t *testing.T) {
	c := NewUseRPC("http://127.0.0.1:8545")
	flag, err := c.UseIsMiner("0x6da8c30181d22e69fb17fa498f5cba5b09ecd572", "latest")
	fmt.Println("Is a miner", err, flag)
}

func TestRPCMainTransaction(t *testing.T) {
	c := NewUseRPC("http://127.0.0.1:8545")
	tx := T {
		From: "0x6da8c30181d22e69fb17fa498f5cba5b09ecd572",
		To:   "0xfffffffffffffffffffffffffffffffff0000001",
		Value: big.NewInt(0),
		Data:  "",
	}
	flag, err := c.UseSendSubTransaction(tx, "0x6da8c30181d22e69fb17fa498f5cba5b09ecd572", "latest")
	fmt.Println("The tx hash:", err, flag)
}