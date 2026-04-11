package shield

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
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
			register[reg] = gen.selectRegister()
		}
	case 64:
		for _, reg := range registerX64 {
			register[reg] = gen.selectRegister()
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
			register[reg] = gen.selectRegister()
		}
	case 64:
		for _, reg := range regVolatileX64 {
			register[reg] = gen.selectRegister()
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
			register[reg] = gen.selectRegister()
		}
	case 64:
		for _, reg := range regNonvolatileX64 {
			register[reg] = gen.selectRegister()
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
func (gen *Generator) selectRegister() string {
	idx := gen.rand.Intn(len(gen.regBox))
	reg := gen.regBox[idx]
	// remove selected register
	gen.regBox = append(gen.regBox[:idx], gen.regBox[idx+1:]...)
	return reg
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
