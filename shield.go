package shield

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"text/template"
)

// methods for provide to the shield.
const (
	methodSleep = 1 // hide Gleam-RT and sleep
	methodExit  = 2 // free Gleam-RT and exit
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

var (
	//go:embed shield/shield_x86.asm
	defaultShieldX86 string

	//go:embed shield/shield_x64.asm
	defaultShieldX64 string
)

type shieldCtx struct {
	// for replace registers
	Reg  map[string]string
	RegV map[string]string
	RegN map[string]string

	// for random immediate data
	Less16 map[string]int // [1, 15]
	Less32 map[string]int // [1, 31]
	Less64 map[string]int // [1, 63]
}

func (gen *Generator) buildShield(shield string) (output string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	if shield == "" {
		switch gen.arch {
		case 32:
			shield = gen.getShieldX86()
		case 64:
			shield = gen.getShieldX64()
		}
	}
	tpl, err := template.New("shield").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"iji": gen.insertJunkInst,
	}).Parse(shield)
	if err != nil {
		return "", fmt.Errorf("invalid shield template: %s", err)
	}
	Less16 := make(map[string]int)
	Less32 := make(map[string]int)
	Less64 := make(map[string]int)
	for i := 'A'; i <= 'Z'; i++ {
		less16 := 1 + gen.rand.Intn(15)
		less32 := 1 + gen.rand.Intn(31)
		less64 := 1 + gen.rand.Intn(63)
		Less16[string(i+0x00)] = less16
		Less16[string(i+0x20)] = less16
		Less32[string(i+0x00)] = less32
		Less32[string(i+0x20)] = less32
		Less64[string(i+0x00)] = less64
		Less64[string(i+0x20)] = less64
	}
	ctx := &shieldCtx{
		Reg:    gen.buildRandomRegisterMap(),
		RegV:   gen.buildVolatileRegisterMap(),
		RegN:   gen.buildNonvolatileRegisterMap(),
		Less16: Less16,
		Less32: Less32,
		Less64: Less64,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, ctx)
	if err != nil {
		return "", fmt.Errorf("failed to build shield source: %s", err)
	}
	return buf.String(), nil
}

func (gen *Generator) getShieldX86() string {
	tpl := gen.opts.ShieldX86
	if tpl != "" {
		return tpl
	}
	return defaultShieldX86
}

func (gen *Generator) getShieldX64() string {
	tpl := gen.opts.ShieldX64
	if tpl != "" {
		return tpl
	}
	return defaultShieldX64
}
