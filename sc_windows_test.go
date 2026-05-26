package shield

import (
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

	procVirtualFree           = modKernel32.NewProc("VirtualFree")
	procVirtualProtect        = modKernel32.NewProc("VirtualProtect")
	procWaitForSingleObject   = modKernel32.NewProc("WaitForSingleObject")
	procCreateWaitableTimerA  = modKernel32.NewProc("CreateWaitableTimerA")
	procSetWaitableTimer      = modKernel32.NewProc("SetWaitableTimer")
	procFlushInstructionCache = modKernel32.NewProc("FlushInstructionCache")
	procExitThread            = modKernel32.NewProc("ExitThread")
)

type testSleepArgs struct {
	Method              uintptr
	VirtualProtect      uintptr
	WaitForSingleObject uintptr
	Reserved            uintptr
	CriticalAddress     uintptr
	CriticalSize        uintptr
	DecoyAddress        uintptr
	DecoySize           uintptr
	ShelterAddress      uintptr
	TimerHandle         uintptr
}

type testFreeArgs struct {
	Method          uintptr
	VirtualProtect  uintptr
	VirtualFree     uintptr
	ExitThread      uintptr
	CriticalAddress uintptr
	CriticalSize    uintptr
	DecoyAddress    uintptr
	DecoySize       uintptr
}

func testShield(t *testing.T, shield []byte, sleep time.Duration) {
	critical := make([]byte, 8192)
	copy(critical, "runtime instruction")
	var decoy []byte
	switch runtime.GOARCH {
	case "386":
		decoy = testAddX86
	case "amd64":
		decoy = testAddX64
	default:
		panic("unsupported architecture")
	}
	shelter := make([]byte, 16384)

	shieldAddr := testDeployShield(t, shield)
	criticalAddr := uintptr(unsafe.Pointer(&critical[0]))
	decoyAddr := uintptr(unsafe.Pointer(&decoy[0]))
	shelterAddr := uintptr(unsafe.Pointer(&shelter[0]))
	t.Logf("shield address:   0x%X\n", shieldAddr)
	t.Logf("critical address: 0x%X\n", criticalAddr)
	t.Logf("decoy address:    0x%X\n", decoyAddr)
	t.Logf("shelter address:  0x%X\n", shelterAddr)

	now := time.Now()

	args := testBuildSleepArgs(t, critical, decoy, shelter, sleep)
	_, _, _ = syscall.SyscallN(shieldAddr, uintptr(unsafe.Pointer(args)))
	err := windows.CloseHandle(windows.Handle(args.TimerHandle))
	require.NoError(t, err)

	args = testBuildSleepArgs(t, critical, decoy, shelter, sleep)
	args.VirtualProtect = 0 // not adjust critical page protect
	_, _, _ = syscall.SyscallN(shieldAddr, uintptr(unsafe.Pointer(args)))
	err = windows.CloseHandle(windows.Handle(args.TimerHandle))
	require.NoError(t, err)

	require.Greater(t, time.Since(now), sleep*2)
	require.True(t, strings.HasPrefix(string(critical), "runtime instruction"))
	require.NotZero(t, binary.LittleEndian.Uint64(shelter[:8]))

	// prevent compiler optimization
	runtime.KeepAlive(critical)
	runtime.KeepAlive(shelter)
}

func testBuildSleepArgs(t *testing.T, critical, decoy, shelter []byte, sleep time.Duration) *testSleepArgs {
	hTimer, _, err := procCreateWaitableTimerA.Call(0, 0, 0)
	if hTimer == 0 {
		require.NoError(t, err)
	}
	dueTime := -sleep.Milliseconds() * 1000 * 10
	ok, _, err := procSetWaitableTimer.Call(
		hTimer, uintptr(unsafe.Pointer(&dueTime)), 0, 0, 0, 1,
	)
	require.True(t, ok == 1, err)

	args := &testSleepArgs{
		Method:              methodSleep,
		VirtualProtect:      procVirtualProtect.Addr(),
		WaitForSingleObject: procWaitForSingleObject.Addr(),
		CriticalAddress:     uintptr(unsafe.Pointer(&critical[0])),
		CriticalSize:        uintptr(len(critical)),
		DecoyAddress:        uintptr(unsafe.Pointer(&decoy[0])),
		DecoySize:           uintptr(len(decoy)),
		ShelterAddress:      uintptr(unsafe.Pointer(&shelter[0])),
		TimerHandle:         hTimer,
	}
	return args
}

func testBuildFreeArgs(critical, decoy []byte) *testFreeArgs {
	args := &testFreeArgs{
		Method:          methodFree,
		VirtualProtect:  procVirtualProtect.Addr(),
		VirtualFree:     procVirtualFree.Addr(),
		ExitThread:      procExitThread.Addr(),
		CriticalAddress: uintptr(unsafe.Pointer(&critical[0])),
		CriticalSize:    uintptr(len(critical)),
		DecoyAddress:    uintptr(unsafe.Pointer(&decoy[0])),
		DecoySize:       uintptr(len(decoy)),
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
