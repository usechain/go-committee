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

package utils

import (
	"testing"
	"fmt"
)

func TestBitCount(t *testing.T) {
	fmt.Println(BitCount(234))
}

func TestArray(t *testing.T) {
	var m [][]string = make([][]string, 5)
	var n []string = make([]string, 5)

	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			m[i] = append(m[i], string(i+52))
		}
		n[i] = string(i+65)
	}
	fmt.Println(m)
	fmt.Println(n)

	res := randomCombineSet(m, n)
	fmt.Println(res)

	fmt.Println(expandStringArray(n))
}

func TestPermutationStrings(t *testing.T) {
	var m [][]string = make([][]string, 5)

	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			m[i] = append(m[i], string(i*5+j+65))
		}
	}
	fmt.Println(m)
	n := PermutationStrings(m)
	fmt.Println(n)
}
