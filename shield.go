package shield

import (
	"bytes"
	"embed"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

var (
	//go:embed shield/shield_x86.asm
	defaultTemplateX86 string

	//go:embed shield/shield_x64.asm
	defaultTemplateX64 string
)

var (
	registerX86 = []string{
		"eax", "ebx", "ecx", "edx",
		"ebp", "edi", "esi",
	}

	regVolatileX86 = []string{
		"eax", "ecx", "edx",
	}

	regNonvolatileX86 = []string{
		"ebx", "ebp", "edi", "esi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rdi", "rsi",
		"r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15",
	}

	regVolatileX64 = []string{
		"rax", "rcx", "rdx",
		"r8", "r9", "r10", "r11",
	}

	regNonvolatileX64 = []string{
		"rbx", "rbp", "rdi", "rsi",
		"r12", "r13", "r14", "r15",
	}
)

type shieldCtx struct {
	// for replace registers
	RegV map[string]string
	RegN map[string]string
}

func (gen *Generator) buildShield(src string) (string, error) {
	var shield string
	switch gen.arch {
	case 32:
		shield = gen.getTemplateX86()
	case 64:
		shield = gen.getTemplateX64()
	}
	if src != "" {
		shield = src
	}
	ctx := &shieldCtx{
		RegV: gen.buildVolatileRegisterMap(),
		RegN: gen.buildNonvolatileRegisterMap(),
	}
	tpl, err := template.New("shield").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": gen.insertGarbageInst,
	}).Parse(shield)
	if err != nil {
		return "", fmt.Errorf("invalid shield template: %s", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, ctx)
	if err != nil {
		return "", fmt.Errorf("failed to build shield source: %s", err)
	}
	return buf.String(), nil
}

func toDB(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(".byte ")
	for i := 0; i < len(b); i++ {
		builder.WriteString("0x")
		s := hex.EncodeToString([]byte{b[i]})
		builder.WriteString(strings.ToUpper(s))
		builder.WriteString(", ")
	}
	return builder.String()
}

func toHex(v any) string {
	return fmt.Sprintf("0x%X", v)
}

// convert r8 -> r8d, rax -> eax
func toRegDWORD(reg string) string {
	_, err := strconv.Atoi(reg[1:])
	if err == nil {
		return reg + "d"
	}
	return strings.ReplaceAll(reg, "r", "e")
}
