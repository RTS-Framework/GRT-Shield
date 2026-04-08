package shield

import (
	cr "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/For-ACGN/go-keystone"
)

// Generator is the runtime shield generator.
type Generator struct {
	rand *rand.Rand

	// assembler engine
	ase32 *keystone.Engine
	ase64 *keystone.Engine

	// context arguments
	arch int
	opts *Options

	// for select random register
	regBox []string
}

// Options contains options about generate shield.
type Options struct {
	// disable garbage instruction, not recommend.
	NoGarbage bool `toml:"no_garbage" json:"no_garbage"`

	// specify a random seed for generator.
	RandSeed int64 `toml:"rand_seed" json:"rand_seed"`

	// specify the x86 shield template.
	ShieldX86 string `toml:"shield_x86" json:"shield_x86"`

	// specify the x64 shield template.
	ShieldX64 string `toml:"shield_x64" json:"shield_x64"`

	// specify the x86 junk code templates.
	JunkCodeX86 []string `toml:"junk_code_x86" json:"junk_code_x86"`

	// specify the x64 junk code templates.
	JunkCodeX64 []string `toml:"junk_code_x64" json:"junk_code_x64"`
}

// Context contains the output and context data in Generate.
type Context struct {
	Output []byte `json:"output"`
	Seed   int64  `json:"seed"`
}

// NewGenerator is used to create a shield generator.
func NewGenerator() *Generator {
	var seed int64
	buf := make([]byte, 8)
	_, err := cr.Read(buf)
	if err == nil {
		seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
	} else {
		seed = time.Now().UTC().UnixNano()
	}
	generator := Generator{
		rand: rand.New(rand.NewSource(seed)), // #nosec
	}
	return &generator
}

// Generate is used to generate a new random shield.
func (gen *Generator) Generate(arch int, opts *Options) (ctx *Context, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	switch arch {
	case 32, 64:
	default:
		return nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	if opts == nil {
		opts = new(Options)
	}
	gen.arch = arch
	gen.opts = opts
	// initialize keystone engine
	err = gen.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = gen.rand.Int63()
	}
	gen.rand.Seed(seed)
	// build shield source from template
	shield, err := gen.buildShield("")
	if err != nil {
		return nil, fmt.Errorf("failed to build shield: %s", err)
	}
	output, err := gen.assemble(shield)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble shield source: %s", err)
	}
	// build context for test and debug
	ctx = &Context{
		Output: output,
		Seed:   seed,
	}
	return ctx, nil
}

func (gen *Generator) initAssembler() error {
	var (
		ase *keystone.Engine
		err error
	)
	switch gen.arch {
	case 32:
		if gen.ase32 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		if err != nil {
			return err
		}
		gen.ase32 = ase
	case 64:
		if gen.ase64 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		if err != nil {
			return err
		}
		gen.ase64 = ase
	default:
		panic("unreachable code")
	}
	return ase.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
}

func (gen *Generator) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	if strings.Contains(src, "<nil>") {
		return nil, errors.New("invalid usage in assembly source")
	}
	switch gen.arch {
	case 32:
		return gen.ase32.Assemble(src, 0)
	case 64:
		return gen.ase64.Assemble(src, 0)
	default:
		panic("unreachable code")
	}
}

// Close is used to close shield generator.
func (gen *Generator) Close() error {
	if gen.ase32 != nil {
		err := gen.ase32.Close()
		if err != nil {
			return err
		}
	}
	if gen.ase64 != nil {
		err := gen.ase64.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
