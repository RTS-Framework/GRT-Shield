package shield

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"text/template"
)

// The role of the junk code is to make the instruction sequence
// as featureless as possible.
var (
	//go:embed junk/*_x86.asm
	defaultJunkCodeFSx86 embed.FS

	//go:embed junk/*_x64.asm
	defaultJunkCodeFSx64 embed.FS

	defaultJunkCodeX86 = readJunkCodeTemplates(defaultJunkCodeFSx86)
	defaultJunkCodeX64 = readJunkCodeTemplates(defaultJunkCodeFSx64)
)

func readJunkCodeTemplates(efs embed.FS) []string {
	var templates []string
	err := fs.WalkDir(efs, ".", func(name string, entry fs.DirEntry, _ error) error {
		if entry.IsDir() {
			return nil
		}
		file, err := efs.Open(name)
		if err != nil {
			panic(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		templates = append(templates, string(data))
		return nil
	})
	if err != nil {
		panic(err)
	}
	return templates
}

type junkCodeCtx struct {
	// for replace registers
	Reg map[string]string

	// for insert random instruction pair
	Switch map[string]bool

	// for random immediate data
	BYTE  map[string]int8
	WORD  map[string]int16
	DWORD map[string]int32
	QWORD map[string]int64

	// for random immediate data with [0, 32) and [0, 64)
	Less32 map[string]int
	Less64 map[string]int
}

func (gen *Generator) insertJunkInst() string {
	if gen.opts.NoJunkCode {
		return ""
	}
	return ";" + toDB(gen.buildJunkInst())
}

func (gen *Generator) buildJunkInst() []byte {
	if gen.opts.NoJunkCode {
		return nil
	}
	// random not insert junk instruction
	if gen.rand.Intn(10) == 0 {
		return nil
	}
	var numJunkCodes int
	switch gen.arch {
	case 32:
		numJunkCodes = len(gen.getJunkCodeX86())
	case 64:
		numJunkCodes = len(gen.getJunkCodeX64())
	}
	// dynamically adjust probability
	switch gen.rand.Intn(2 + numJunkCodes) {
	case 0:
		return nil
	case 1:
		return gen.junkMultiByteNOP()
	default:
		return gen.junkTemplate()
	}
}

func (gen *Generator) junkMultiByteNOP() []byte {
	var nop []byte
	switch gen.rand.Intn(2) {
	case 0:
		nop = []byte{0x90}
	case 1:
		nop = []byte{0x66, 0x90}
	}
	return nop
}

func (gen *Generator) junkTemplate() []byte {
	var junkCodes []string
	switch gen.arch {
	case 32:
		junkCodes = gen.getJunkCodeX86()
	case 64:
		junkCodes = gen.getJunkCodeX64()
	}
	// select random junk code template
	idx := gen.rand.Intn(len(junkCodes))
	src := junkCodes[idx]
	asm, err := gen.buildJunkCode(src)
	if err != nil {
		panic(err)
	}
	// assemble junk code
	inst, err := gen.assemble(asm)
	if err != nil {
		panic(fmt.Sprintf("failed to assemble junk code: %s", err))
	}
	return inst
}

func (gen *Generator) getJunkCodeX86() []string {
	if len(gen.opts.JunkCodeX86) > 0 {
		return gen.opts.JunkCodeX86
	}
	return defaultJunkCodeX86
}

func (gen *Generator) getJunkCodeX64() []string {
	if len(gen.opts.JunkCodeX64) > 0 {
		return gen.opts.JunkCodeX64
	}
	return defaultJunkCodeX64
}

// #nosec G115
func (gen *Generator) buildJunkCode(src string) (string, error) {
	// process assembly source
	tpl, err := template.New("junk_code").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"iji": gen.insertJunkInst,
	}).Parse(src)
	if err != nil {
		return "", fmt.Errorf("invalid junk code template: %s", err)
	}
	// initialize random data
	switches := make(map[string]bool)
	BYTE := make(map[string]int8)
	WORD := make(map[string]int16)
	DWORD := make(map[string]int32)
	QWORD := make(map[string]int64)
	Less32 := make(map[string]int)
	Less64 := make(map[string]int)
	for i := 'A'; i <= 'Z'; i++ {
		b := gen.rand.Intn(2) == 0
		i8 := int8(gen.rand.Int31() % 128)
		i16 := int16(gen.rand.Int31() % 32768)
		i32 := gen.rand.Int31()
		i64 := gen.rand.Int63()
		l32 := gen.rand.Intn(32)
		l64 := gen.rand.Intn(64)
		switches[string(i+0x00)] = b
		switches[string(i+0x20)] = b
		BYTE[string(i+0x00)] = i8
		BYTE[string(i+0x20)] = i8
		WORD[string(i+0x00)] = i16
		WORD[string(i+0x20)] = i16
		DWORD[string(i+0x00)] = i32
		DWORD[string(i+0x20)] = i32
		QWORD[string(i+0x00)] = i64
		QWORD[string(i+0x20)] = i64
		Less32[string(i+0x00)] = l32
		Less32[string(i+0x20)] = l32
		Less64[string(i+0x00)] = l64
		Less64[string(i+0x20)] = l64
	}
	ctx := junkCodeCtx{
		Reg:    gen.buildRandomRegisterMap(),
		Switch: switches,
		BYTE:   BYTE,
		WORD:   WORD,
		DWORD:  DWORD,
		QWORD:  QWORD,
		Less32: Less32,
		Less64: Less64,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", fmt.Errorf("failed to build junk code assembly source: %s", err)
	}
	return buf.String(), nil
}
