//go:build !windows

package shield

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testShield(t *testing.T, shield []byte, sleep time.Duration) {
	require.NotEmpty(t, shield)
}
