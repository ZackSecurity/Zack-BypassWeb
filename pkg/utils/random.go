// Zack-BypassWeb - 冰蝎4.1 免杀Webshell生成框架
// Copyright (C) 2024 Zack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package utils

import (
	"crypto/rand"
	"math/big"
)

const (
	lowerAlpha = "abcdefghijklmnopqrstuvwxyz"
	upperAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits     = "0123456789"
	allChars   = lowerAlpha + upperAlpha + digits
	alphaChars = lowerAlpha + upperAlpha
)

// RandString generates a crypto-random string of given length starting with a letter.
func RandString(length int) string {
	if length <= 0 {
		length = 8
	}
	buf := make([]byte, length)
	// First char must be alpha
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphaChars))))
	buf[0] = alphaChars[n.Int64()]
	for i := 1; i < length; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		buf[i] = allChars[n.Int64()]
	}
	return string(buf)
}

// RandInt returns a crypto-random int in [min, max].
func RandInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

// RandCommentBody generates random comment text for injection.
func RandCommentBody() string {
	patterns := []string{
		RandString(RandInt(3, 8)),
		RandString(RandInt(2, 5)) + "*" + RandString(RandInt(2, 5)),
		"_" + RandString(RandInt(3, 6)),
		RandString(2) + "::" + RandString(4),
		"$" + RandString(RandInt(4, 7)),
		"#" + RandString(RandInt(3, 6)) + RandString(RandInt(1, 3)),
		"~" + RandString(RandInt(2, 6)),
		RandString(1) + "/" + RandString(RandInt(2, 5)),
		"@" + RandString(RandInt(3, 6)),
		"&" + RandString(RandInt(3, 7)),
		"#" + RandString(RandInt(4, 8)) + "_" + RandString(RandInt(2, 4)),
		RandString(RandInt(4, 6)) + "##" + RandString(RandInt(2, 4)),
		"@" + RandString(3) + "->" + RandString(4),
	}
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(patterns))))
	return patterns[idx.Int64()]
}
