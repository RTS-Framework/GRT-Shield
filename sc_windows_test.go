package shield

import (
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procVirtualProtect        = modKernel32.NewProc("VirtualProtect")
	procWaitForSingleObject   = modKernel32.NewProc("WaitForSingleObject")
	procCreateWaitableTimerA  = modKernel32.NewProc("CreateWaitableTimerA")
	procSetWaitableTimer      = modKernel32.NewProc("SetWaitableTimer")
	procFlushInstructionCache = modKernel32.NewProc("FlushInstructionCache")
)

type testShieldArgs struct {
	VirtualProtect      uintptr
	WaitForSingleObject uintptr
	CriticalAddress     uintptr
	CriticalSize        uintptr
	ShelterAddress      uintptr
	TimerHandle         uintptr
	CryptoKey           uintptr
}

func testShield(t *testing.T, shield []byte, sleep time.Duration) {
	critical := make([]byte, 8192)
	copy(critical, "runtime instruction")
	criticalAddr := uintptr(unsafe.Pointer(&critical[0]))

	address := testDeployShield(t, shield)
	t.Logf("data address:   0x%X\n", criticalAddr)
	t.Logf("shield address: 0x%X\n", address)

	now := time.Now()

	args := testBuildShieldArgs(t, critical, sleep)
	_, _, _ = syscall.SyscallN(address, uintptr(unsafe.Pointer(args)))
	err := windows.CloseHandle(windows.Handle(args.TimerHandle))
	require.NoError(t, err)

	args = testBuildShieldArgs(t, critical, sleep)
	_, _, _ = syscall.SyscallN(address, uintptr(unsafe.Pointer(args)))
	err = windows.CloseHandle(windows.Handle(args.TimerHandle))
	require.NoError(t, err)

	require.Greater(t, time.Since(now), sleep*2)
	require.True(t, strings.HasPrefix(string(critical), "runtime instruction"))
}

func testBuildShieldArgs(t *testing.T, critical []byte, sleep time.Duration) *testShieldArgs {
	hTimer, _, err := procCreateWaitableTimerA.Call(0, 0, 0)
	if hTimer == 0 {
		require.NoError(t, err)
	}
	dueTime := -sleep.Milliseconds() * 1000 * 10
	ok, _, err := procSetWaitableTimer.Call(
		hTimer, uintptr(unsafe.Pointer(&dueTime)), 0, 0, 0, 1,
	)
	require.True(t, ok == 1, err)

	buf := make([]byte, 8)
	_, err = rand.Read(buf)
	require.NoError(t, err)
	cryptoKey := uintptr(binary.LittleEndian.Uint64(buf))

	args := &testShieldArgs{
		VirtualProtect:      procVirtualProtect.Addr(),
		WaitForSingleObject: procWaitForSingleObject.Addr(),
		CriticalAddress:     uintptr(unsafe.Pointer(&critical[0])),
		CriticalSize:        uintptr(len(critical)),
		TimerHandle:         hTimer,
		CryptoKey:           cryptoKey,
	}
	return args
}

// try to write shield in .text section
func testDeployShield(t *testing.T, shield []byte) uintptr {
	exe, err := os.Executable()
	require.NoError(t, err)
	img, err := pe.Open(exe)
	require.NoError(t, err)

	// calculate the code cave size
	var (
		pageSize uint32
		caveSize uint32
	)
	switch runtime.GOARCH {
	case "386":
		pageSize = img.OptionalHeader.(*pe.OptionalHeader32).SectionAlignment
	case "amd64":
		pageSize = img.OptionalHeader.(*pe.OptionalHeader64).SectionAlignment
	default:
		t.Fatal("unsupported architecture")
	}
	text := img.Sections[0]
	require.Equal(t, text.Name, ".text")
	pageOffset := text.VirtualSize & (pageSize - 1)
	if pageOffset != 0 {
		caveSize = pageSize - pageOffset
	}
	if int(caveSize) <= len(shield) {
		return loadShellcode(t, shield)
	}

	// write shield to the code cave
	peb := windows.RtlGetCurrentPeb()
	address := peb.ImageBaseAddress + uintptr(text.VirtualAddress+text.VirtualSize)
	size := uintptr(len(shield))
	var old uint32
	err = windows.VirtualProtect(address, size, windows.PAGE_READWRITE, &old)
	require.NoError(t, err)

	dst := unsafe.Slice((*byte)(unsafe.Pointer(address)), size)
	copy(dst, shield)

	err = windows.VirtualProtect(address, size, old, &old)
	require.NoError(t, err)
	r1, _, err := procFlushInstructionCache.Call(
		uintptr(windows.CurrentProcess()), address, size,
	)
	require.NotZero(t, r1, err)
	return address
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}
