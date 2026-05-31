package shield

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJunkCode(t *testing.T) {
	generator := NewGenerator()

	opts := &Options{
		NoJunkCode: false,
	}

	t.Run("x86", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			ctx, err := generator.Generate(32, opts)
			if err == ErrShieldSizeTooLarge {
				continue
			}
			require.NoError(t, err)

			t.Log("size:", len(ctx.Output))
			t.Log(ctx.ShieldInst)

			if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
				return
			}

			testShield(t, ctx.Output, testSleepTime)
			return
		}
		t.Fatal("failed to generate shield")
	})

	t.Run("x64", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			ctx, err := generator.Generate(64, opts)
			if err == ErrShieldSizeTooLarge {
				continue
			}
			require.NoError(t, err)

			t.Log("size:", len(ctx.Output))
			t.Log(ctx.ShieldInst)

			if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
				return
			}

			testShield(t, ctx.Output, testSleepTime)
			return
		}
		t.Fatal("failed to generate shield")
	})

	t.Run("invalid template", func(t *testing.T) {
		opts.JunkCodeX86 = []string{"{{.Invalid}}"}

		ctx, err := generator.Generate(32, opts)
		require.ErrorContains(t, err, "failed to build junk code assembly source")
		require.Nil(t, ctx)
	})

	t.Run("empty output", func(t *testing.T) {
		opts.JunkCodeX86 = []string{""}

		ctx, err := generator.Generate(32, opts)
		require.ErrorContains(t, err, "empty output junk code assembly source")
		require.Nil(t, ctx)
	})

	t.Run("invalid source", func(t *testing.T) {
		opts.JunkCodeX86 = []string{"invalid"}

		ctx, err := generator.Generate(32, opts)
		errStr := "failed to assemble junk code: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.ErrorContains(t, err, errStr)
		require.Nil(t, ctx)
	})

	t.Run("unknown error", func(t *testing.T) {
		opts.JunkCodeX86 = []string{"// unknown op"}

		ctx, err := generator.Generate(32, opts)
		require.ErrorContains(t, err, "assemble junk code source with unknown error")
		require.Nil(t, ctx)
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestJunkTemplateFuzz(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		generator := NewGenerator()
		generator.arch = 32
		generator.opts = new(Options)
		err := generator.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := generator.junkTemplate()
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
			data := generator.junkTemplate()
			require.NotEmpty(t, data)
		}

		err = generator.Close()
		require.NoError(t, err)
	})
}
