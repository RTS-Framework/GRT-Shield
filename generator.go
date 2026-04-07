package shield

import (
	cr "crypto/rand"
	"encoding/binary"
	"errors"
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
	TemplateX86 string `toml:"template_x86" json:"template_x86"`

	// specify the x64 shield template.
	TemplateX64 string `toml:"template_x64" json:"template_x64"`

	// specify the x86 junk code templates.
	JunkCodeX86 []string `toml:"junk_code_x86" json:"junk_code_x86"`

	// specify the x64 junk code templates.
	JunkCodeX64 []string `toml:"junk_code_x64" json:"junk_code_x64"`
}

// Context contains the output and context data in Generate.
type Context struct {
	Output []byte `toml:"output" json:"output"`
	Seed   int64  `toml:"seed"   json:"seed"`
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
