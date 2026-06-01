package shield

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerator(t *testing.T) {
	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			ctx, err := generator.Generate(32, nil)
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
		for i := 0; i < 10; i++ {
			ctx, err := generator.Generate(64, nil)
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

	t.Run("invalid arch", func(t *testing.T) {
		ctx, err := generator.Generate(123, nil)
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, ctx)
	})

	opts := new(Options)

	t.Run("invalid template", func(t *testing.T) {
		opts.ShieldX86 = "{{.Invalid}}"

		ctx, err := generator.Generate(32, opts)
		require.ErrorContains(t, err, "failed to build shield source")
		require.Nil(t, ctx)
	})

	t.Run("invalid source", func(t *testing.T) {
		opts.ShieldX86 = "invalid"

		ctx, err := generator.Generate(32, opts)
		errStr := "failed to assemble shield: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.ErrorContains(t, err, errStr)
		require.Nil(t, ctx)
	})

	t.Run("unknown error", func(t *testing.T) {
		opts.ShieldX86 = "// unknown op"

		ctx, err := generator.Generate(32, opts)
		require.EqualError(t, err, "assemble shield source with unknown error")
		require.Nil(t, ctx)
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestSpecificSeed(t *testing.T) {
	generator := NewGenerator()

	opts := &Options{
		RandSeed: 1234,
	}

	t.Run("x86", func(t *testing.T) {
		ctx1, err := generator.Generate(32, opts)
		require.NoError(t, err)
		ctx2, err := generator.Generate(32, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}

		testShield(t, ctx1.Output, testSleepTime)
	})

	t.Run("x64", func(t *testing.T) {
		ctx1, err := generator.Generate(64, opts)
		require.NoError(t, err)
		ctx2, err := generator.Generate(64, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}

		testShield(t, ctx1.Output, testSleepTime)
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestGeneratorFuzz(t *testing.T) {
	const sleepTime = 50 * time.Millisecond

	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			ctx, err := generator.Generate(32, nil)
			if err == ErrShieldSizeTooLarge {
				continue
			}
			require.NoError(t, err)
			t.Log("size:", len(ctx.Output))
			t.Log("seed:", ctx.Seed)

			if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
				continue
			}

			testShield(t, ctx.Output, sleepTime)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			ctx, err := generator.Generate(64, nil)
			if err == ErrShieldSizeTooLarge {
				continue
			}
			require.NoError(t, err)
			t.Log("size:", len(ctx.Output))
			t.Log("seed:", ctx.Seed)

			if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
				continue
			}

			testShield(t, ctx.Output, sleepTime)
		}
	})

	err := generator.Close()
	require.NoError(t, err)
}
