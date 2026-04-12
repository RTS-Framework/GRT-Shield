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
	var registers []string
	switch gen.arch {
	case 32:
		registers = registerX86
	case 64:
		registers = registerX64
	}
	reg := gen.shuffleRegisterMap(registers)
	if gen.arch == 64 {
		gen.buildLowBitRegisterMap(reg)
	}
	return reg
}

func (gen *Generator) shuffleRegisterMap(registers []string) map[string]string {
	src := registers
	dst := slices.Clone(registers)
	for {
		gen.rand.Shuffle(len(dst), func(i, j int) {
			dst[i], dst[j] = dst[j], dst[i]
		})
		ok := true
		for i := 0; i < len(src); i++ {
			if src[i] == dst[i] {
				ok = false
			}
		}
		if ok {
			break
		}
	}
	reg := make(map[string]string, len(src))
	for i := 0; i < len(src); i++ {
		reg[src[i]] = dst[i]
	}
	return reg
}

func (gen *Generator) buildVolatileRegisterMap() map[string]string {
	var registers []string
	switch gen.arch {
	case 32:
		registers = slices.Clone(regVolatileX86)
	case 64:
		registers = slices.Clone(regVolatileX64)
	}
	gen.regBox = registers
	regMap := make(map[string]string, len(registers))
	switch gen.arch {
	case 32:
		for _, reg := range regVolatileX86 {
			regMap[reg] = gen.selectRegisterMap(reg)
		}
	case 64:
		for _, reg := range regVolatileX64 {
			regMap[reg] = gen.selectRegisterMap(reg)
		}
		gen.buildLowBitRegisterMap(regMap)
	}
	return regMap
}

func (gen *Generator) buildNonvolatileRegisterMap() map[string]string {
	var registers []string
	switch gen.arch {
	case 32:
		registers = slices.Clone(regNonvolatileX86)
	case 64:
		registers = slices.Clone(regNonvolatileX64)
	}
	gen.regBox = registers
	regMap := make(map[string]string, len(registers))
	switch gen.arch {
	case 32:
		for _, reg := range regNonvolatileX86 {
			regMap[reg] = gen.selectRegisterMap(reg)
		}
	case 64:
		for _, reg := range regNonvolatileX64 {
			regMap[reg] = gen.selectRegisterMap(reg)
		}
		gen.buildLowBitRegisterMap(regMap)
	}
	return regMap
}

func (gen *Generator) buildLowBitRegisterMap(regMap map[string]string) {
	// build register map about low dword
	low := make(map[string]string, len(regMap))
	for src, dst := range regMap {
		low[toRegDWORD(src)] = toRegDWORD(dst)
	}
	maps.Copy(regMap, low)
}

// selectRegisterMap is used to make sure each register will be selected once.
func (gen *Generator) selectRegisterMap(src string) string {
	var (
		idx int
		dst string
	)
	for {
		idx = gen.rand.Intn(len(gen.regBox))
		dst = gen.regBox[idx]
		if dst != src {
			break
		}
		if len(gen.regBox) <= 1 {
			break
		}
	}
	// remove selected register
	gen.regBox = append(gen.regBox[:idx], gen.regBox[idx+1:]...)
	return dst
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
