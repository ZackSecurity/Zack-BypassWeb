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

package evasion

import (
	"fmt"
	"Zack-BypassWeb/pkg/utils"
	"strings"
)

// VarPool manages a set of polymorphic variable names for one generation.
type VarPool struct {
	vars  []string
	used  map[string]bool
	index int
}

// NewVarPool creates a pool of random variable names.
func NewVarPool(count int) *VarPool {
	vp := &VarPool{
		vars: make([]string, 0, count),
		used: make(map[string]bool),
	}
	prefixes := []string{"a", "b", "c", "d", "e", "f", "g", "h", "k", "l", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
	for i := 0; i < count; i++ {
		prefix := prefixes[utils.RandInt(0, len(prefixes)-1)]
		name := prefix + utils.RandString(utils.RandInt(3, 7))
		// Ensure uniqueness
		for vp.used[name] {
			name = prefix + utils.RandString(utils.RandInt(3, 7))
		}
		vp.used[name] = true
		vp.vars = append(vp.vars, name)
	}
	return vp
}

// Get returns the next variable from the pool.
func (vp *VarPool) Get() string {
	if vp.index >= len(vp.vars) {
		// Generate new one if exhausted
		name := utils.RandString(8)
		vp.vars = append(vp.vars, name)
	}
	v := vp.vars[vp.index]
	vp.index++
	return v
}

// GetN returns n variables as a slice.
func (vp *VarPool) GetN(n int) []string {
	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = vp.Get()
	}
	return result
}

// GetAll returns all unused variables.
func (vp *VarPool) GetAll() []string {
	return vp.vars[vp.index:]
}


// PHPVarPool generates PHP-style variable names ($ prefix).
type PHPVarPool VarPool

// NewPHPVarPool creates PHP variable pool.
func NewPHPVarPool(count int) *PHPVarPool {
	vp := &PHPVarPool{
		vars: make([]string, 0, count),
		used: make(map[string]bool),
	}
	prefixes := []string{"a", "b", "c", "d", "e", "f", "g", "h", "k", "l", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
	for i := 0; i < count; i++ {
		prefix := prefixes[utils.RandInt(0, len(prefixes)-1)]
		name := "$" + prefix + utils.RandString(utils.RandInt(3, 7))
		for vp.used[name] {
			name = "$" + prefix + utils.RandString(utils.RandInt(3, 7))
		}
		vp.used[name] = true
		vp.vars = append(vp.vars, name)
	}
	return vp
}

// Get returns the next PHP variable.
func (vp *PHPVarPool) Get() string {
	if vp.index >= len(vp.vars) {
		name := "$" + utils.RandString(8)
		vp.vars = append(vp.vars, name)
	}
	v := vp.vars[vp.index]
	vp.index++
	return v
}

// GetN returns n PHP variables.
func (vp *PHPVarPool) GetN(n int) []string {
	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = vp.Get()
	}
	return result
}

// GetAll returns all remaining unused variables.
func (vp *PHPVarPool) GetAll() []string {
	return vp.vars[vp.index:]
}

// CommentInjection generates a random comment for injection between method calls.
type CommentInjection struct {
	style string // "java", "php", "asp", "csharp"
}

// NewCommentInjection creates a new comment injector.
func NewCommentInjection(style string) *CommentInjection {
	return &CommentInjection{style: style}
}

// Generate returns a random comment fragment for injection.
func (ci *CommentInjection) Generate() string {
	body := utils.RandCommentBody()
	switch ci.style {
	case "java":
		styles := []string{
			fmt.Sprintf("/*%s*/", body),
			fmt.Sprintf("/*%s*/", body+"_"+utils.RandString(3)),
			fmt.Sprintf("/*%s*/", utils.RandString(2)+":"+body),
			fmt.Sprintf("/*%s*/", body+"_"+utils.RandString(utils.RandInt(1, 4))),
			fmt.Sprintf("/*%s*/", strings.ToUpper(utils.RandString(1))+body),
			fmt.Sprintf("/**%s**/", body),
			fmt.Sprintf("/*%s*/", body+"_"+utils.RandString(utils.RandInt(2, 5))+"_t"),
		}
		return styles[utils.RandInt(0, len(styles)-1)]
	case "php":
		return fmt.Sprintf("/*%s*/", body)
	case "asp":
		return "' " + body
	case "csharp":
		styles := []string{
			fmt.Sprintf("/*%s*/", body),
			fmt.Sprintf("/*%s*/", body+"."+utils.RandString(3)),
			fmt.Sprintf("/*%s*/", utils.RandString(2)+"@"+body),
		}
		return styles[utils.RandInt(0, len(styles)-1)]
	default:
		return fmt.Sprintf("/*%s*/", body)
	}
}

