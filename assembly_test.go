package shield

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testAddX86 = []byte{
		0x31, 0xC0, //               xor eax, eax
		0x03, 0x44, 0x24, 0x04, //   add eax, [esp+04]
		0x03, 0x44, 0x24, 0x08, //   add eax, [esp+08]
		0xC2, 0x08, 0x00, //         ret 8
	}

	testAddX64 = []byte{
		0x31, 0xC0, //               xor eax, eax
		0x48, 0x01, 0xC8, //         add rax, rcx
		0x48, 0x01, 0xD0, //         add rax, rdx
		0xC3, //                     ret
	}
)

func TestBuildRandomRegisterMap(t *testing.T) {
	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		generator.arch = 32
		err := generator.initAssembler()
		require.NoError(t, err)

		regMap := generator.buildRandomRegisterMap()
		for src, dst := range regMap {
			t.Logf("%s -> %s\n", src, dst)
			require.NotEqual(t, src, dst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		generator.arch = 64
		err := generator.initAssembler()
		require.NoError(t, err)

		regMap := generator.buildRandomRegisterMap()
		for src, dst := range regMap {
			t.Logf("%s -> %s\n", src, dst)
			require.NotEqual(t, src, dst)
		}
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestBuildVolatileRegisterMap(t *testing.T) {
	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		generator.arch = 32
		err := generator.initAssembler()
		require.NoError(t, err)

		regMap := generator.buildVolatileRegisterMap()
		for src, dst := range regMap {
			t.Logf("%s -> %s\n", src, dst)
			require.NotEqual(t, src, dst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		generator.arch = 64
		err := generator.initAssembler()
		require.NoError(t, err)

		regMap := generator.buildVolatileRegisterMap()
		for src, dst := range regMap {
			t.Logf("%s -> %s\n", src, dst)
			require.NotEqual(t, src, dst)
		}
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestBuildNonvolatileRegisterMap(t *testing.T) {
	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		generator.arch = 32
		err := generator.initAssembler()
		require.NoError(t, err)

		regMap := generator.buildNonvolatileRegisterMap()
		for src, dst := range regMap {
			t.Logf("%s -> %s\n", src, dst)
			require.NotEqual(t, src, dst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		generator.arch = 64
		err := generator.initAssembler()
		require.NoError(t, err)

		regMap := generator.buildNonvolatileRegisterMap()
		for src, dst := range regMap {
			t.Logf("%s -> %s\n", src, dst)
			require.NotEqual(t, src, dst)
		}
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestPrintInstructions(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		binHex, insts, err := printInstructions(testAddX86, 32)
		require.NoError(t, err)
		t.Log(binHex)
		t.Log(insts)
	})

	t.Run("x64", func(t *testing.T) {
		binHex, insts, err := printInstructions(testAddX64, 64)
		require.NoError(t, err)
		t.Log(binHex)
		t.Log(insts)
	})
}

func TestToDB(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte{1, 2, 3, 4}
		output := toDB(data)

		expected := ".byte 0x01, 0x02, 0x03, 0x04, "
		require.Equal(t, expected, output)
	})

	t.Run("empty bytes", func(t *testing.T) {
		output := toDB(nil)
		require.Empty(t, output)
	})
}

func TestToHex(t *testing.T) {
	output := toHex(15)
	require.Equal(t, "0xF", output)
}

func TestToRegDWORD(t *testing.T) {
	for _, item := range []*struct {
		input  string
		output string
	}{
		{"rax", "eax"},
		{"rbx", "ebx"},
		{"rcx", "ecx"},
		{"rdx", "edx"},
		{"rdi", "edi"},
		{"rsi", "esi"},
		{"rsp", "esp"},
		{"r8", "r8d"},
		{"r9", "r9d"},
		{"r10", "r10d"},
		{"r11", "r11d"},
		{"r12", "r12d"},
		{"r13", "r13d"},
		{"r14", "r14d"},
		{"r15", "r15d"},
	} {
		output := toRegDWORD(item.input)
		require.Equal(t, item.output, output)
	}
}
