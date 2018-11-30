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

package sssa

import (
	"testing"
	"math/big"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
	"fmt"
	"crypto/ecdsa"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-committee/utils"

)

func TestSingleShamir(t *testing.T) {
	created, _, polynomials, err := Create256Bit(2,3, big.NewInt(188888888111111111))
	if err != nil {
		fmt.Println("err", err)
		return
	}
	combined, err := Combine256Bit(created)
	fmt.Println("The combined num:", combined)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}

	polyPublicKeys := ToECDSAPubArray(polynomials)

	fmt.Println("creates", created)
	fmt.Println("polyPublicKeys", polyPublicKeys)
	fmt.Println("res：", VerifyCreatedAndPolynomial(created, polyPublicKeys))
}

const shares = 3

func TestMultiShamir(t *testing.T) {
	var creates [][]string = make([][]string, shares)
	var pointers [][]*big.Int = make([][]*big.Int, shares)
	var polynomials [][]*big.Int = make([][]*big.Int, shares)
	var err error
	var tmp *big.Int

	privSum := big.NewInt(0)

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	for i := 0; i < shares; i++ {
		tmp = random()
		fmt.Println("Tmp number:", tmp)
		creates[i], pointers[i], polynomials[i], err = Create256Bit(2,3, tmp)
		if err != nil {
			fmt.Println("err", err)
			return
		}

		fmt.Println(creates[i])

		combined, err := Combine256Bit(creates[i])
		if err != nil {
			fmt.Println("Fatal: combining: ", err)
		}
		fmt.Println("The combined num:", combined)

		privSum.Add(privSum, combined)
		privSum.Mod(privSum, prime)
	}
	fmt.Println("The privSum", privSum)

	//Generate shares
	var shareSelf []*big.Int = make([]*big.Int, shares)
	var result []string = make([]string, shares)
	for i := 0; i < shares; i++ {
		shareSelf[i] = big.NewInt(0)
		for j := 0; j < shares; j++ {
			//fmt.Printf("pointers[j][i]: %x\n", pointers[j][i])
			shareSelf[i].Add(shareSelf[i], pointers[j][i])
			shareSelf[i].Mod(shareSelf[i], prime)
		}

		result[i] += utils.ToBase64(big.NewInt(int64(i+1)))
		result[i] += utils.ToBase64(shareSelf[i])
		fmt.Println("share", result[i])
	}

	//Combine the shares
	combined, err := Combine256Bit(result)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}
	fmt.Println("The combined privSum:", combined)

	//Sum(shareSelf[]) == Sum(di)
	//So, Sum(shareSelf[]*G) = Sum(di) * G
	var privKeys []*ecdsa.PrivateKey = make([]*ecdsa.PrivateKey, shares)
	var pubShares []string = make([]string, shares)
	for i := 0; i < shares; i++ {
		privKeys[i] = generatePrivKey(shareSelf[i])
		pubShares[i] += utils.ToBase64(big.NewInt(int64(i+1)))
		pubShares[i] += utils.ToBase64(privKeys[i].PublicKey.X)
		pubShares[i] += utils.ToBase64(privKeys[i].PublicKey.Y)
	}

	fmt.Println(pubShares)
	//Combine the pub shares
	_, err = CombineECDSAPubkey(pubShares[1:])
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}

	//The raw pubkey
	rawPub := generatePrivKey(combined)
	fmt.Println("the raw pubkey ", rawPub.PublicKey)

}

func TestClient(t *testing.T) {
	// committee generate a random number, di
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Crit(fmt.Sprintf("Failed to generate ephemeral node key: %v", err))
	}

	// generate shares
	created, _, polynomials, err := Create256Bit(2,3, priv.D)
	if err != nil {
		fmt.Println("err", err)
		return
	}
	combined, err := Combine256Bit(created)
	if err != nil || combined.Cmp(priv.D) != 0 {
		fmt.Println("Fatal: combining: ", err)
	}

	polyPublicKeys := ToECDSAPubArray(polynomials)

	if !VerifyCreatedAndPolynomial(created, polyPublicKeys) {
		fmt.Println("Fatal: verifying: ", err)
	}

}

const CommitteeKey = "0x04b8f04cc7fdfce5eed37983f43cd5ac8ef7efd56d6e6ed218b3f534d86f2489794d7060d39a583608247016306870abd2b23a808212ba9cfd675f1b0a09b4b02f"

func TestABGenerate(t *testing.T) {
	mainPriv, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("key generate failed, err:", err)
		return
	}

	sPriv, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("key generate failed, err:", err)
		return
	}

	B := crypto.ToECDSAPub(common.FromHex(CommitteeKey))
	_, a1, _, _ :=crypto.GenerteABPrivateKey(mainPriv, sPriv, hexutil.Encode(B.X.Bytes()), hexutil.Encode(B.Y.Bytes()), hexutil.Encode(sPriv.PublicKey.X.Bytes()), hexutil.Encode(sPriv.PublicKey.Y.Bytes()))
	a2 := generatePrivKey(a1.D)

	fmt.Println("a2", a2)
}

func TestPubCombine(t *testing.T) {
	pubs := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=LdgGcT19mQjNfzssgoOm_uVs8Inw_DBosgEELKud-Yo=4NibcQAIvnPKdW8yCbp6PPS2UsxfpjCiCsgdkFMMB4E=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=LdgGcT19mQjNfzssgoOm_uVs8Inw_DBosgEELKud-Yo=4NibcQAIvnPKdW8yCbp6PPS2UsxfpjCiCsgdkFMMB4E=",
	}

	S := common.FromHex("04def73063a9e17e22a8e91f7b41a019d03f5dbc4d29055474211e7f7d4e4620ba59005cd78a0294efc15330d900603d6d4665db7a09d35f065be3f65b04513f56")
	SPub := crypto.ToECDSAPub(S)

	combined, _ := CombineECDSAPubkey(pubs)

	A1sub := ScanPubSharesA1(combined, SPub)
	fmt.Printf("%x\n", crypto.FromECDSAPub(&A1sub))


}

func TestSecretCombine(t *testing.T) {
	shares := []string{//"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=mZfEnYvTuEejlN5z_4JZz1TyXFOAzq8NEmqsttA_y7Y=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=cvNINT0A67rlVoAyyfp59syyp8ivwIVKiudR2lDlSms=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=TE7LzO4uHy4nGCHxlHKaHkRy8z3esluIA2P2_dGKySA=",
	}
	combined, err := Combine256Bit(shares)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}
	fmt.Println("The combined string:", combined)


	pub := generatePrivKey(combined).PublicKey
	fmt.Println(pub)
	fmt.Printf("%x\n", crypto.FromECDSAPub(&pub))
}

func TestSharesKeyCombine(t *testing.T) {
	privs := []string{ "90893478833360206723751331124192505180059212859377926804796661845896909951562",
		"78445727432136860286068254473714872394751088232989457663907484034549238116334",
		"33403409495031834235444390667264193166862923077198418946013147149530103008266"}
	a,_ := big.NewInt(0).SetString(privs[0], 10)
	b,_ := big.NewInt(0).SetString(privs[1], 10)
	c,_ := big.NewInt(0).SetString(privs[2], 10)

	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	d := big.NewInt(0).Add(a, b)
	e := big.NewInt(0).Add(d, c)
	fmt.Println(e)
	f := big.NewInt(0).Mod(e, prime)
	fmt.Println(f)

	pub := generatePrivKey(f).PublicKey
	fmt.Println(generatePrivKey(f).PublicKey)
	fmt.Printf("%x\n", crypto.FromECDSAPub(&pub))
}


func TestPubKeyCombine(t *testing.T) {
	privs := []string{ "90893478833360206723751331124192505180059212859377926804796661845896909951562",
		"78445727432136860286068254473714872394751088232989457663907484034549238116334",
		"33403409495031834235444390667264193166862923077198418946013147149530103008266"}
	a,_ := big.NewInt(0).SetString(privs[0], 10)
	b,_ := big.NewInt(0).SetString(privs[1], 10)
	c,_ := big.NewInt(0).SetString(privs[2], 10)

	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	apub := generatePrivKey(a).PublicKey
	bpub := generatePrivKey(b).PublicKey
	cpub := generatePrivKey(c).PublicKey

	sum := new(ecdsa.PublicKey)
	sum.Curve = crypto.S256()
	sum.X, sum.Y = crypto.S256().Add(apub.X, apub.Y, bpub.X, bpub.Y)
	sum.X, sum.Y = crypto.S256().Add(sum.X, sum.Y, cpub.X, cpub.Y)

	fmt.Printf("sun pub:%x\n", crypto.FromECDSAPub(sum))

}

func TestABaccount(t *testing.T) {
	a, _ := hexutil.Decode("0xe02081d45513fb8c03080aff502cb4354fe32e3a039338035d61aa81156db22e")
	B := common.FromHex("04b8f04cc7fdfce5eed37983f43cd5ac8ef7efd56d6e6ed218b3f534d86f2489794d7060d39a583608247016306870abd2b23a808212ba9cfd675f1b0a09b4b02f")
	S := common.FromHex("04def73063a9e17e22a8e91f7b41a019d03f5dbc4d29055474211e7f7d4e4620ba59005cd78a0294efc15330d900603d6d4665db7a09d35f065be3f65b04513f56")

	tmp,_ := big.NewInt(0).SetString("e02081d45513fb8c03080aff502cb4354fe32e3a039338035d61aa81156db22e", 16)
	aPriv := generatePrivKey(tmp)

	BPub := crypto.ToECDSAPub(B)
	SPub := crypto.ToECDSAPub(S)
	fmt.Println(BPub, SPub)

	A1 := crypto.ScanA1(a, BPub, SPub)

	fmt.Println(A1)
	fmt.Printf("%x\n", crypto.FromECDSAPub(&A1))


	A := aPriv.PublicKey
	b,_ := big.NewInt(0).SetString("86950526523212705821692991256483662888835659890490899032112129888458089581825", 10)

	fmt.Println("A", A)
	fmt.Println("Spub", SPub)
	A1sub := crypto.ScanA1(b.Bytes(), &A, SPub)
	fmt.Printf("%x\n", crypto.FromECDSAPub(&A1sub))

}


func TestExtractPrivateShare(t *testing.T) {
	fmt.Println(ExtractPrivateShare("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=cvNINT0A67rlVoAyyfp59syyp8ivwIVKiudR2lDlSms="))
}
