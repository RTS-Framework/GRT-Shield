package shield

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGarbage(t *testing.T) {
	generator := NewGenerator()

	opts := &Options{
		NoGarbage: false,
	}

	t.Run("x86", func(t *testing.T) {
		ctx, err := generator.Generate(32, opts)
		require.NoError(t, err)
		t.Log("size:", len(ctx.Output))

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}

		testShield(t, ctx.Output, testSleepTime)
	})

	t.Run("x64", func(t *testing.T) {
		ctx, err := generator.Generate(64, opts)
		require.NoError(t, err)
		t.Log("size:", len(ctx.Output))

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}

		testShield(t, ctx.Output, testSleepTime)
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestGarbageTemplateFuzz(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		generator := NewGenerator()
		generator.arch = 32
		generator.opts = new(Options)
		err := generator.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := generator.garbageTemplate()
			require.NotEmpty(t, data)
		}

		err = generator.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		generator := NewGenerator()
		generator.arch = 64
		generator.opts = new(Options)
		err := generator.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := generator.garbageTemplate()
			require.NotEmpty(t, data)
		}

		err = generator.Close()
		require.NoError(t, err)
	})
}
