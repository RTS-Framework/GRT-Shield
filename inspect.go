package shield

import (
	"fmt"
)

// InspectShieldTemplate is used to test shield template.
func InspectShieldTemplate(arch int, src string) (string, []byte, error) {
	switch arch {
	case 32, 64:
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	generator := NewGenerator()
	generator.arch = arch
	generator.opts = &Options{
		NoJunkCode: true,
	}
	defer func() { _ = generator.Close() }()
	err := generator.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := generator.buildShield(src)
	if err != nil {
		return "", nil, err
	}
	inst, err := generator.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble shield: %s", err)
	}
	err = generator.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}

// InspectJunkCodeTemplate is used to test junk code template.
func InspectJunkCodeTemplate(arch int, src string) (string, []byte, error) {
	switch arch {
	case 32, 64:
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	generator := NewGenerator()
	generator.arch = arch
	generator.opts = new(Options)
	defer func() { _ = generator.Close() }()
	err := generator.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := generator.buildJunkCode(src)
	if err != nil {
		return "", nil, err
	}
	inst, err := generator.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble junk code: %s", err)
	}
	err = generator.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}
