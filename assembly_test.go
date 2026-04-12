package shield

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildRandomRegisterMap(t *testing.T) {
	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		generator.arch = 32
		err := generator.initAssembler()
		require.NoError(t, err)

		m := generator.buildRandomRegisterMap()
		for k, v := range m {
			require.NotEqual(t, k, v)
			fmt.Printf("%s -> %s\n", k, v)
		}
	})

	t.Run("x64", func(t *testing.T) {
		generator.arch = 64
		err := generator.initAssembler()
		require.NoError(t, err)

		m := generator.buildRandomRegisterMap()
		for k, v := range m {
			require.NotEqual(t, k, v)
			fmt.Printf("%s -> %s\n", k, v)
		}
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestBuildVolatileRegisterMap(t *testing.T) {

}

func TestBuildNonvolatileRegisterMap(t *testing.T) {

}

func TestPrintInstructions(t *testing.T) {

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
