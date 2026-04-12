package shield

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
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

func (gen *Generator) buildRandomRegisterMap() map[string]string {
	var reg []string
	switch gen.arch {
	case 32:
		reg = slices.Clone(registerX86)
	case 64:
		reg = slices.Clone(registerX64)
	}
	gen.regBox = reg
	register := make(map[string]string, 16)
	switch gen.arch {
	case 32:
		for _, reg := range registerX86 {
			register[reg] = gen.selectRegister(reg)
		}
	case 64:
		for _, reg := range registerX64 {
			register[reg] = gen.selectRegister(reg)
		}
		gen.buildLowBitRegisterMap(register)
	}
	return register
}

func (gen *Generator) buildVolatileRegisterMap() map[string]string {
	var reg []string
	switch gen.arch {
	case 32:
		reg = slices.Clone(regVolatileX86)
	case 64:
		reg = slices.Clone(regVolatileX64)
	}
	gen.regBox = reg
	register := make(map[string]string, len(reg))
	switch gen.arch {
	case 32:
		for _, reg := range regVolatileX86 {
			register[reg] = gen.selectRegister(reg)
		}
	case 64:
		for _, reg := range regVolatileX64 {
			register[reg] = gen.selectRegister(reg)
		}
		gen.buildLowBitRegisterMap(register)
	}
	return register
}

func (gen *Generator) buildNonvolatileRegisterMap() map[string]string {
	var reg []string
	switch gen.arch {
	case 32:
		reg = slices.Clone(regNonvolatileX86)
	case 64:
		reg = slices.Clone(regNonvolatileX64)
	}
	gen.regBox = reg
	register := make(map[string]string, len(reg))
	switch gen.arch {
	case 32:
		for _, reg := range regNonvolatileX86 {
			register[reg] = gen.selectRegister(reg)
		}
	case 64:
		for _, reg := range regNonvolatileX64 {
			register[reg] = gen.selectRegister(reg)
		}
		gen.buildLowBitRegisterMap(register)
	}
	return register
}

func (gen *Generator) buildLowBitRegisterMap(register map[string]string) {
	// build register map about low dword
	low := make(map[string]string, len(register))
	for reg, act := range register {
		low[toRegDWORD(reg)] = toRegDWORD(act)
	}
	maps.Copy(register, low)
}

// selectRegister is used to make sure each register will be selected once.
func (gen *Generator) selectRegister(reg string) string {
	var (
		i int
		r string
	)
	for {
		i = gen.rand.Intn(len(gen.regBox))
		r = gen.regBox[i]
		if r != reg {
			break
		}
	}
	// remove selected register
	gen.regBox = append(gen.regBox[:i], gen.regBox[i+1:]...)
	return r
}

func printInstructions(src []byte, mode int) (string, string, error) {
	binHex := strings.Builder{}
	insts := strings.Builder{}
	for len(src) > 0 {
		inst, err := x86asm.Decode(src, mode)
		if err != nil {
			return "", "", err
		}
		b := src[:inst.Len]
		binHex.WriteString(printAssemblyBinHex(&inst, b))
		binHex.Write([]byte("\r\n"))
		insts.WriteString(printAssemblyInstruction(&inst))
		insts.Write([]byte("\r\n"))
		src = src[inst.Len:]
	}
	return binHex.String(), insts.String(), nil
}

func printAssemblyBinHex(inst *x86asm.Inst, b []byte) string {
	var bin strings.Builder
	switch {
	case inst.PCRelOff != 0:
		s1 := strings.ToUpper(hex.EncodeToString(b[:inst.PCRelOff]))
		s2 := strings.ToUpper(hex.EncodeToString(b[inst.PCRelOff:]))
		bin.WriteString(s1)
		bin.WriteString(" ")
		bin.WriteString(s2)
	default:
		s := strings.ToUpper(hex.EncodeToString(b))
		bin.WriteString(s)
	}
	return bin.String()
}

func printAssemblyInstruction(inst *x86asm.Inst) string {
	var buf bytes.Buffer
	for _, p := range inst.Prefix {
		if p == 0 {
			break
		}
		if p&x86asm.PrefixImplicit != 0 {
			continue
		}
		_, _ = fmt.Fprintf(&buf, "%s ", strings.ToLower(p.String()))
	}
	_, _ = fmt.Fprintf(&buf, "%s", strings.ToLower(inst.Op.String()))
	sep := " "
	for _, v := range inst.Args {
		if v == nil {
			break
		}
		_, _ = fmt.Fprintf(&buf, "%s%s", sep, strings.ToLower(v.String()))
		sep = ", "
	}
	return buf.String()
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
