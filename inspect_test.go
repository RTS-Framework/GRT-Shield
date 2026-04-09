package shield

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestInspectShieldTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		asm, inst, err := InspectShieldTemplate(32, defaultShieldX86)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		asm, inst, err := InspectShieldTemplate(64, defaultShieldX64)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectShieldTemplate(123, "")
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})
}

func TestInspectJunkCodeTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, src := range defaultJunkCodeX86 {
			asm, inst, err := InspectJunkCodeTemplate(32, src)
			require.NoError(t, err)
			fmt.Println(asm)
			spew.Dump(inst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, src := range defaultJunkCodeX64 {
			asm, inst, err := InspectJunkCodeTemplate(64, src)
			require.NoError(t, err)
			fmt.Println(asm)
			spew.Dump(inst)
		}
	})

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate(123, "")
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})
}
