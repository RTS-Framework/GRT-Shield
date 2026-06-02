package shield

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"runtime"
	"strings"
	"sync"
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
	procCreateThread          = modKernel32.NewProc("CreateThread")
	procGetExitCodeThread     = modKernel32.NewProc("GetExitCodeThread")
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

type testExitArgs struct {
	Method          uintptr
	VirtualProtect  uintptr
	VirtualFree     uintptr
	ExitThread      uintptr
	CriticalAddress uintptr
	CriticalSize    uintptr
	DecoyAddress    uintptr
	DecoySize       uintptr
}

type testExitCtx struct {
	Shield uintptr
	Args   *testExitArgs
}

func testShield(t *testing.T, shield []byte, sleep time.Duration) {
	shieldAddr := testDeployShield(t, shield)
	testShieldSleep(t, shieldAddr, sleep)
	testShieldExit(t, shieldAddr)
}

func testShieldSleep(t *testing.T, shield uintptr, sleep time.Duration) {
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

	criticalAddr := uintptr(unsafe.Pointer(&critical[0]))
	decoyAddr := uintptr(unsafe.Pointer(&decoy[0]))
	shelterAddr := uintptr(unsafe.Pointer(&shelter[0]))

	t.Logf("shield address:   0x%X\n", shield)
	t.Logf("critical address: 0x%X\n", criticalAddr)
	t.Logf("decoy address:    0x%X\n", decoyAddr)
	t.Logf("shelter address:  0x%X\n", shelterAddr)

	wg := sync.WaitGroup{}
	checker := func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			hasDecoy := bytes.Equal(critical[:len(decoy)], decoy)
			if hasDecoy {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		panic("decoy is not deploy")
	}

	now := time.Now()

	// common adjust critical
	var old uint32
	err := windows.VirtualProtect(criticalAddr, uintptr(len(critical)), windows.PAGE_READONLY, &old)
	require.NoError(t, err)

	wg.Add(1)
	go checker()

	args := testBuildSleepArgs(t, critical, decoy, shelter, sleep)
	_, _, _ = syscall.SyscallN(shield, uintptr(unsafe.Pointer(args)))
	err = windows.CloseHandle(windows.Handle(args.TimerHandle))
	require.NoError(t, err)

	wg.Wait()

	err = windows.VirtualProtect(criticalAddr, uintptr(len(critical)), old, &old)
	require.NoError(t, err)

	// not adjust critical page protect
	wg.Add(1)
	go checker()

	args = testBuildSleepArgs(t, critical, decoy, shelter, sleep)
	args.VirtualProtect = 0
	_, _, _ = syscall.SyscallN(shield, uintptr(unsafe.Pointer(args)))
	err = windows.CloseHandle(windows.Handle(args.TimerHandle))
	require.NoError(t, err)

	wg.Wait()

	// check total elapsed time and compare data
	deviation := 10 * time.Millisecond // about Windows CPU Scheduler
	require.Greater(t, time.Since(now), sleep*2-deviation)
	require.True(t, strings.HasPrefix(string(critical), "runtime instruction"))
	require.NotZero(t, binary.LittleEndian.Uint64(shelter[:8]))

	// prevent compiler optimization
	runtime.KeepAlive(critical)
	runtime.KeepAlive(decoy)
	runtime.KeepAlive(shelter)
}

func testShieldExit(t *testing.T, shield uintptr) {
	criticalSize := uintptr(8192)
	allocType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	criticalAddr, err := windows.VirtualAlloc(0, criticalSize, allocType, windows.PAGE_READWRITE)
	require.NoError(t, err)
	critical := unsafe.Slice((*byte)(unsafe.Pointer(criticalAddr)), criticalSize)
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

	decoyAddr := uintptr(unsafe.Pointer(&decoy[0]))

	t.Logf("shield address:   0x%X\n", shield)
	t.Logf("critical address: 0x%X\n", criticalAddr)
	t.Logf("decoy address:    0x%X\n", decoyAddr)

	args := testBuildExitArgs(critical, decoy)

	// run shield in a dedicated thread because
	// ExitThread will terminate the calling thread
	callback := syscall.NewCallback(func(lpParameter uintptr) uintptr {
		ctx := (*testExitCtx)(unsafe.Pointer(lpParameter))
		_, _, _ = syscall.SyscallN(ctx.Shield, uintptr(unsafe.Pointer(ctx.Args)))
		return 0 // unreachable
	})
	ctx := &testExitCtx{
		Shield: shield,
		Args:   args,
	}
	hThread, _, err := procCreateThread.Call(
		0, 0, callback, uintptr(unsafe.Pointer(ctx)), 0, 0,
	)
	require.NotZero(t, hThread, err)

	// wait for thread to exit
	ret, _, err := procWaitForSingleObject.Call(hThread, 1000)
	require.Equal(t, uintptr(windows.WAIT_OBJECT_0), ret, err)

	// verify thread exit code = 0
	exitCode := uintptr(123)
	_, _, _ = procGetExitCodeThread.Call(hThread, uintptr(unsafe.Pointer(&exitCode)))
	require.Equal(t, uintptr(0), exitCode)

	err = windows.CloseHandle(windows.Handle(hThread))
	require.NoError(t, err)

	// the shield called VirtualFree on critical,
	// verify it was freed double VirtualFree should fail
	ret, _, _ = procVirtualFree.Call(criticalAddr, 0, windows.MEM_RELEASE)
	require.Zero(t, ret)

	// prevent compiler optimization
	runtime.KeepAlive(critical)
	runtime.KeepAlive(decoy)
	runtime.KeepAlive(ctx)
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

func testBuildExitArgs(critical, decoy []byte) *testExitArgs {
	args := &testExitArgs{
		Method:          methodExit,
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
