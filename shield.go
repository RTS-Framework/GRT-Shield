package shield

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"text/template"
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
	RegV map[string]string
	RegN map[string]string
}

func (gen *Generator) buildShield(src string) (output string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	var shield string
	switch gen.arch {
	case 32:
		shield = gen.getShieldX86()
	case 64:
		shield = gen.getShieldX64()
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
