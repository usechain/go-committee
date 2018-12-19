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
	"math/big"
	"crypto/ecdsa"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/common"
)

/**
 * Returns a new array of secret shares and polynomial
 * created by Shamir's Secret Sharing Algorithm requring a minimum number of
 * share to recreate, of length shares, from the input secret raw as a big.Int
**/
func Create256Bit(minimum int, shares int, raw *big.Int) ([]string, []*big.Int, []*big.Int, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.
	if minimum > shares || raw.BitLen() > 256 {
		return []string{""}, []*big.Int{}, []*big.Int{}, ErrCannotRequireMoreShares
	}

	// Convert the secret to its respective 256-bit big.Int representation
	//var secret []*big.Int = make([]*big.Int, 1)
	//secret[0] = raw
	secret := raw

	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// List of currently used numbers in the polynomial
	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))

	// Create the polynomial of degree (minimum - 1); that is, the highest
	// order term is (minimum-1), though as there is a constant term with
	// order 0, there are (minimum) number of coefficients.
	//
	// However, the polynomial object is a 2d array, because we are constructing
	// a different polynomial for each part of the secret
	// polynomial[parts][minimum]
	var polynomial []*big.Int = make([]*big.Int, minimum)
	polynomial[0] = secret

	for j := range polynomial[1:] {
		// Each coefficient should be unique
		number := random()
		for inNumbers(numbers, number) {
			number = random()
		}
		numbers = append(numbers, number)

		polynomial[j+1] = number
	}

	// Create the secrets object; this holds the (x, y) points of each share.
	// Again, because secret is an array, each share could have multiple parts
	// over which we are computing Shamir's Algorithm. The last dimension is
	// always two, as it is storing an x, y pair of points.
	//
	// In the usehchain key, x ->>>> 1 ~ sharesNum  ///TODO: committee id
	// The point is 1, 2, 3, 4 ...
	// Calculate the f(hash(index))

	var pointer []*big.Int= make([]*big.Int, shares)
	var result []string = make([]string, shares)
	index := big.NewInt(1)
	for i := 0; i < shares; i++ {
		// ...and every part of the secret...
		pointer[i] = evaluatePolynomial(polynomial, index)
		result[i] += utils.ToBase64(index)
		result[i] += utils.ToBase64(pointer[i])

		//fmt.Printf("The number is %d, f(%d):%x\n:", index, index, pointer[i])
		index.Add(index, big.NewInt(1))

	}

	// ...and returns
	return result, pointer, polynomial, nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
**/
func Combine256Bit(shares []string) (*big.Int, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets [][]*big.Int = make([][]*big.Int, len(shares))

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// For each share...
	for i := range shares {
		// ...ensure that it is valid...
		if IsValidShare256Bit(shares[i]) == false {
			return big.NewInt(-1), ErrOneOfTheSharesIsInvalid
		}

		// ...find the number of parts it represents...
		share := shares[i]
		secrets[i] = make([]*big.Int, 1)

		// ...and for each part, find the x,y pair...

		cshare := share[0 : 88]
		secrets[i] = make([]*big.Int, 2)
		// ...decoding from base 64.
		secrets[i][0] = utils.FromBase64(cshare[0:44])
		secrets[i][1] = utils.FromBase64(cshare[44:])
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	secret := big.NewInt(0)

	// ...and every share...
	for i := range secrets { // LPI sum loop
		// ...remember the current x and y values...
		origin := secrets[i][0]
		originy := secrets[i][1]
		numerator := big.NewInt(1)   // LPI numerator
		denominator := big.NewInt(1) // LPI denominator
		// ...and for every other point...
		for k := range secrets { // LPI product loop
			if k != i {
				// ...combine them via half products...
				current := secrets[k][0]
				negative := big.NewInt(0)
				negative = negative.Mul(current, big.NewInt(-1))
				added := big.NewInt(0)
				added = added.Sub(origin, current)

				numerator = numerator.Mul(numerator, negative)
				numerator = numerator.Mod(numerator, prime)

				denominator = denominator.Mul(denominator, added)
				denominator = denominator.Mod(denominator, prime)
			}
		}

		// LPI product
		// ...multiply together the points (y)(numerator)(denominator)^-1...
		working := big.NewInt(0).Set(originy)
		working = working.Mul(working, numerator)
		working = working.Mul(working, modInverse(denominator))

		// LPI sum
		secret = secret.Add(secret, working)
		secret = secret.Mod(secret, prime)
	}


	// ...and return the result!
	return secret, nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
**/
func CombineECDSAPubkey(shares []string) (*ecdsa.PublicKey, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))
	var secretPubs []*ecdsa.PublicKey = make([]*ecdsa.PublicKey, len(shares))

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// For each share...
	for i := range shares {
		// ...ensure that it is valid...
		if IsValidShare(shares[i]) == false {
			return nil, ErrOneOfTheSharesIsInvalid
		}

		// ...find the number of parts it represents...
		share := shares[i]
		//fmt.Printf("shares[%d]:%x\n", i, share)
		count := len(share) / 132
		secrets[i] = make([][]*big.Int, count)

		// ...and for each part, find the x,y pair...
		for j := range secrets[i] {
			cshare := share[j*132 : (j+1)*132]
			secrets[i][j] = make([]*big.Int, 3)
			// ...decoding from base 64.
			secrets[i][j][0] = utils.FromBase64(cshare[0:44])
			secrets[i][j][1] = utils.FromBase64(cshare[44:88])
			secrets[i][j][2] = utils.FromBase64(cshare[88:])
		}
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret []*big.Int = make([]*big.Int, len(secrets[0]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		// ...and every share...
		for i := range secrets { // LPI sum loop
			// ...remember the current x and y values...
			origin := secrets[i][j][0]
			origin_x := secrets[i][j][1]
			origin_y := secrets[i][j][2]
			numerator := big.NewInt(1)   // LPI numerator
			denominator := big.NewInt(1) // LPI denominator
			// ...and for every other point...
			for k := range secrets { // LPI product loop
				if k != i {
					// ...combine them via half products...
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			// LPI product
			// ...multiply together the points (y)(numerator)(denominator)^-1...
			// but as origin_x & origin_y is a point on elliptic Curve
			param := numerator.Mul(numerator, modInverse(denominator))
			param = param.Mod(param, prime)
			//fmt.Printf("numerator: %x, denominator: %x\n", numerator, denominator)

			A1 := new(ecdsa.PublicKey)
			A1.Curve = crypto.S256()
			A1.X, A1.Y = crypto.S256().ScalarMult(origin_x, origin_y, param.Bytes())   //A1=b_1 * (t_1 * G)

			// LPI sum
			secretPubs[i] = A1
			//fmt.Printf("secretPubs[%d]: %x\n", i, A1)
		}
	}

	res := new(ecdsa.PublicKey)
	res.Curve = crypto.S256()
	if secretPubs[0].X == nil || secretPubs[1].X == nil {
		return nil, ErrOneOfTheSharesIsInvalid
	}
	res.X, res.Y = crypto.S256().Add(secretPubs[0].X, secretPubs[0].Y, secretPubs[1].X, secretPubs[1].Y)
	//fmt.Println("the combined pubkey:", res)

	// ...and return the result!
	return res, nil
}

/**
 *Returns the created shares and polynomials whether match
 * For: f(x) = a0 + a1x + a2x^2 + ... + a(k-1)x^k-1
 *		If get a point (m, f(m)) on line
 *		Should have
 *			f(m)G = a0G + m * a1G + ... + m^(k-1) * a(k-1)G
 * The input share is m + f(m)G share string, the pubkeyArray is the Polynomial Pubkey
**/
func VerifyPolynomial(share string, pubkeyArray []*ecdsa.PublicKey) bool {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secret []*big.Int
	var pubSum ecdsa.PublicKey

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// ...ensure that it is valid...
	if IsValidShare256Bit(share) == false {
		return false
	}

	// ...and for each part, find the x,y pair...
	cshare := share[0 : 88]
	secret = make([]*big.Int, 2)
	// ...decoding from base 64.
	secret[0] = utils.FromBase64(cshare[0:44])
	secret[1] = utils.FromBase64(cshare[44:])

	x := secret[0]
	pubSum.Curve = crypto.S256()

	// a0G + x * a1G + ... + x^(k-1) * a(k-1)G
	for j := range pubkeyArray {
		pubTmp := new(ecdsa.PublicKey)
		pubTmp.Curve = crypto.S256()

		if j == 0 {
			pubSum.X = pubkeyArray[j].X
			pubSum.Y = pubkeyArray[j].Y
			continue
		}
		pubTmp.X, pubTmp.Y  = crypto.S256().ScalarMult(pubkeyArray[j].X, pubkeyArray[j].Y, x.Bytes())
		pubSum.X, pubSum.Y = crypto.S256().Add(pubTmp.X, pubTmp.Y, pubSum.X, pubSum.Y)
		x.Mul(x,x)
	}

	//f(x)
	y := secret[1]
	pubY := generatePrivKey(y).PublicKey

	if !equalECDSAPub(&pubY, &pubSum) {
		return false
	}
	// ...and return the result!
	return true
}

/**
 *Returns the created shares and polynomials whether match
 * For: f(x) = a0 + a1x + a2x^2 + ... + a(k-1)x^k-1
 *		If get a point (m, f(m)) on line
 *		Should have
 *			f(m)G = a0G + m * a1G + ... + m^(k-1) * a(k-1)G
 * The input share is m + f(m)G Shares Array, the pubkeyArray is the Polynomial Pubkey
**/
func VerifyCreatedAndPolynomial(shares []string, pubkeyArray []*ecdsa.PublicKey) bool {
	for i := range shares {
		if !VerifyPolynomial(shares[i], pubkeyArray) {
			return false
		}
	}
	return true
}

//Generate multi-sssa private key from key shares
func GenerateSssaKey(shares []string) *big.Int{
	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	priv := big.NewInt(0)
	for _, share := range shares {
		priv.Add(priv, utils.FromBase64(share[44:]))
		priv.Mod(priv, prime)
	}

	return priv
}

//Generate multi-sssa public key from public key shares
func GenerateCommitteePublicKey(polynomials [][]*ecdsa.PublicKey) *ecdsa.PublicKey {
	sumPub := new(ecdsa.PublicKey)
	sumPub.Curve = crypto.S256()

	for i := range polynomials {
		//fmt.Println("polynomials", polynomials[i][0])
		if 0 == i {
			sumPub.X, sumPub.Y = polynomials[i][0].X, polynomials[i][0].Y
			continue
		}
		sumPub.X, sumPub.Y = crypto.S256().Add(sumPub.X, sumPub.Y, polynomials[i][0].X, polynomials[i][0].Y)
	}
	log.Warn("committee key generated", "publickey", common.ToHex(crypto.FromECDSAPub(sumPub)))
	return sumPub
}
