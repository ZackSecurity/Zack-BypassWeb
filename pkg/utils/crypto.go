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
	"crypto/md5"
	"encoding/hex"
)

// MD5Hash returns the MD5 hex string of input.
func MD5Hash(input string) string {
	h := md5.Sum([]byte(input))
	return hex.EncodeToString(h[:])
}

// MD5Half returns first 16 chars of MD5 hex (the Behinder key).
func MD5Half(input string) string {
	return MD5Hash(input)[:16]
}

