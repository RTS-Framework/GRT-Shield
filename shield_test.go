package shield

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testSleepTime = time.Second

func TestShield(t *testing.T) {
	generator := NewGenerator()

	opts := &Options{
		NoGarbage: true,
		RandSeed:  1234,
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
