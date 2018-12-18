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

package ecies

import (
	"math/big"
	"fmt"
	"io"
	"crypto/subtle"
	"crypto/elliptic"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/go-committee/shamirkey/sssa"
)

type PrivateShare struct {
	Index 	*big.Int
	Key 	*PrivateKey
}

// Import an privateShare
func ImportNormalPrivateShare(share *sssa.PrivateShare) *PrivateShare {
	return &PrivateShare{
		Index:      share.Index,
		Key:		ImportECDSA(sssa.GeneratePrivKey(share.Key)),
	}
}

// ECDH key agreement method used to establish secret keys for encryption.
// Calculate the share * (rG)
func (ps *PrivateShare) ShamirGenerate(pub *PublicKey, skLen, macLen int) (r string, err error) {
	if ps.Key.PublicKey.Curve != pub.Curve {
		return "", ErrInvalidCurve
	}
	if skLen+macLen > MaxSharedKeyLength(pub) {
		return "", ErrSharedKeyTooBig
	}

	x, y := pub.Curve.ScalarMult(pub.X, pub.Y, ps.Key.D.Bytes())
	if x == nil || y == nil {
		return "", ErrSharedKeyIsPointAtInfinity
	}

	r += utils.ToBase64(ps.Index)
	r += utils.ToBase64(x)
	r += utils.ToBase64(y)
	return r, nil
}

// Combine the shares, and recover the k*(rG)
func ShamirShared(pubshares []string, skLen, macLen int) (sk []byte, err error) {
	combine, err := sssa.CombineECDSAPubkey(pubshares)
	if err != nil {
		fmt.Println(err)
		return nil, ErrSharedKeyIsPointAtInfinity
	}
	fmt.Println(combine)
	sk = make([]byte, skLen+macLen)
	skBytes := combine.X.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

// ECIES decryption prepare
func (ps *PrivateShare) ShamirPrepare(rand io.Reader, c, s1, s2 []byte) (res string, keylen int, err error) {
	if len(c) == 0 {
		return "", 0, ErrInvalidMessage
	}
	params := ps.Key.PublicKey.Params
	if params == nil {
		if params = ParamsFromCurve(ps.Key.PublicKey.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}
	hash := params.Hash()
	keylen = params.KeyLen

	var (
		rLen   int
		hLen   int = hash.Size()
	)

	switch c[0] {
	case 2, 3, 4:
		rLen = (ps.Key.PublicKey.Curve.Params().BitSize + 7) / 4
		if len(c) < (rLen + hLen + 1) {
			err = ErrInvalidMessage
			return
		}
	default:
		err = ErrInvalidPublicKey
		return
	}

	R := new(PublicKey)
	R.Curve = ps.Key.PublicKey.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, c[:rLen])
	if R.X == nil {
		err = ErrInvalidPublicKey
		return
	}
	if !R.Curve.IsOnCurve(R.X, R.Y) {
		err = ErrInvalidCurve
		return
	}

	res, err = ps.ShamirGenerate(R, params.KeyLen, params.KeyLen)
	return
}

// Decrypt decrypts an ECIES ciphertext.
func (ps *PrivateShare) ShamirDecrypt(rand io.Reader, z, c, s1, s2 []byte) (m []byte, err error) {
	if len(c) == 0 {
		return nil, ErrInvalidMessage
	}
	params := ps.Key.PublicKey.Params
	if params == nil {
		if params = ParamsFromCurve(ps.Key.PublicKey.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}
	hash := params.Hash()

	var (
		rLen   int
		hLen   int = hash.Size()
		mStart int
		mEnd   int
	)

	switch c[0] {
	case 2, 3, 4:
		rLen = (ps.Key.PublicKey.Curve.Params().BitSize + 7) / 4
		if len(c) < (rLen + hLen + 1) {
			err = ErrInvalidMessage
			return
		}
	default:
		err = ErrInvalidPublicKey
		return
	}

	mStart = rLen
	mEnd = len(c) - hLen

	K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}

	Ke := K[:params.KeyLen]
	Km := K[params.KeyLen:]
	hash.Write(Km)
	Km = hash.Sum(nil)
	hash.Reset()

	d := messageTag(params.Hash, Km, c[mStart:mEnd], s2)
	if subtle.ConstantTimeCompare(c[mEnd:], d) != 1 {
		err = ErrInvalidMessage
		return
	}

	m, err = symDecrypt(rand, params, Ke, c[mStart:mEnd])
	return
}

