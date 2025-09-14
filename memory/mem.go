package memory

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ValueType int

const (
	FourBytes ValueType = iota
	Float
	Double
)

type MemoryProtection uint32

const (
	PAGE_NOACCESS          MemoryProtection = 0x01
	PAGE_READONLY          MemoryProtection = 0x02
	PAGE_READWRITE         MemoryProtection = 0x04
	PAGE_WRITECOPY         MemoryProtection = 0x08
	PAGE_EXECUTE           MemoryProtection = 0x10
	PAGE_EXECUTE_READ      MemoryProtection = 0x20
	PAGE_EXECUTE_READWRITE MemoryProtection = 0x40
	PAGE_EXECUTE_WRITECOPY MemoryProtection = 0x80
)

// Parse some hexadecimal address.
func parseHexAddr(s string) (uintptr, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	_, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	val, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, err
	}
	return uintptr(val), nil
}

// Check if the process is 32-bit (WOW64)
func isProcess32Bit(pid uint32) (bool, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)

	var isWow64 bool
	err = windows.IsWow64Process(handle, &isWow64)
	if err != nil {
		return false, err
	}
	return isWow64, nil
}

// Find some process ID by its name.
func findProcessIDByName(exeName string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if name == exeName {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0, errors.New("process not found")
}

// Returns the base address of the main module of a process
func getModuleBaseAddress(pid uint32, exeName string) (uintptr, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	if err := windows.Module32First(snapshot, &me); err != nil {
		return 0, err
	}

	for {
		name := windows.UTF16ToString(me.Module[:])
		if name == exeName {
			return uintptr(me.ModBaseAddr), nil
		}
		if err := windows.Module32Next(snapshot, &me); err != nil {
			break
		}
	}

	return 0, errors.New("module not found")
}

// Read some memory.
func ReadValue(vt ValueType, exeName, addrStr string) (interface{}, error) {
	pid, err := findProcessIDByName(exeName)
	if err != nil {
		return nil, err
	}
	baseAddr, err := getModuleBaseAddress(pid, exeName)
	if err != nil {
		return nil, err
	}

	offset, err := parseHexAddr(addrStr)
	if err != nil {
		return nil, err
	}
	addr := baseAddr + offset
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var (
		kernel32              = syscall.NewLazyDLL("kernel32.dll")
		procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	)

	switch vt {
	case FourBytes:
		var (
			val       int32
			bytesRead uintptr
		)
		ret, _, callErr := procReadProcessMemory.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 {
			return nil, callErr
		}
		if bytesRead != unsafe.Sizeof(val) {
			return nil, errors.New("failed to read all bytes for FourBytes")
		}
		return val, nil
	case Float:
		var val float32
		var bytesRead uintptr
		ret, _, callErr := procReadProcessMemory.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 {
			return nil, callErr
		}
		if bytesRead != unsafe.Sizeof(val) {
			return nil, errors.New("failed to read all bytes for Float")
		}
		return val, nil
	case Double:
		var val float64
		var bytesRead uintptr
		ret, _, callErr := procReadProcessMemory.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 {
			return nil, callErr
		}
		if bytesRead != unsafe.Sizeof(val) {
			return nil, errors.New("failed to read all bytes for Double")
		}
		return val, nil
	default:
		return nil, errors.New("unsupported ValueType")
	}
}

// Writes a value relative to the main module base + offset
func ChangeValue(vt ValueType, exeName, addrStr string, value interface{}) error {
	pid, err := findProcessIDByName(exeName)
	if err != nil {
		return err
	}

	baseAddr, err := getModuleBaseAddress(pid, exeName)
	if err != nil {
		return err
	}

	offset, err := parseHexAddr(addrStr)
	if err != nil {
		return err
	}

	addr := baseAddr + offset

	handle, err := windows.OpenProcess(windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	var (
		dataPtr  unsafe.Pointer
		dataSize uintptr
	)

	switch vt {
	case FourBytes:
		val, ok := value.(int32)
		if !ok {
			return errors.New("value must be int32 for FourBytes")
		}
		dataPtr = unsafe.Pointer(&val)
		dataSize = unsafe.Sizeof(val)
	case Float:
		val, ok := value.(float32)
		if !ok {
			return errors.New("value must be float32 for Float")
		}
		dataPtr = unsafe.Pointer(&val)
		dataSize = unsafe.Sizeof(val)
	case Double:
		val, ok := value.(float64)
		if !ok {
			return errors.New("value must be float64 for Double")
		}
		dataPtr = unsafe.Pointer(&val)
		dataSize = unsafe.Sizeof(val)
	default:
		return errors.New("unsupported ValueType")
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	var written uintptr
	ret, _, callErr := procWriteProcessMemory.Call(
		uintptr(handle),
		addr,
		uintptr(dataPtr),
		dataSize,
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return callErr
	}
	if written != dataSize {
		return errors.New("failed to write all bytes")
	}

	return nil
}

// Freeze some value by repeatedly writing it to the address
func FreezeValue(vt ValueType, exeName, addrStr string, value any) error {
	pid, err := findProcessIDByName(exeName)
	if err != nil {
		return err
	}

	baseAddr, err := getModuleBaseAddress(pid, exeName)
	if err != nil {
		return err
	}

	offset, err := parseHexAddr(addrStr)
	if err != nil {
		return err
	}

	addr := baseAddr + offset

	handle, err := windows.OpenProcess(windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, pid)
	if err != nil {
		return err
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")

	go func() {
		defer windows.CloseHandle(handle)
		for {
			var dataPtr unsafe.Pointer
			var dataSize uintptr

			switch vt {
			case FourBytes:
				val, ok := value.(int32)
				if !ok {
					return
				}
				dataPtr = unsafe.Pointer(&val)
				dataSize = unsafe.Sizeof(val)
			case Float:
				val, ok := value.(float32)
				if !ok {
					return
				}
				dataPtr = unsafe.Pointer(&val)
				dataSize = unsafe.Sizeof(val)
			case Double:
				val, ok := value.(float64)
				if !ok {
					return
				}
				dataPtr = unsafe.Pointer(&val)
				dataSize = unsafe.Sizeof(val)
			default:
				return
			}

			var written uintptr
			ret, _, _ := procWriteProcessMemory.Call(
				uintptr(handle),
				addr,
				uintptr(dataPtr),
				dataSize,
				uintptr(unsafe.Pointer(&written)),
			)
			if ret == 0 || written != dataSize {
				continue
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	return nil
}

// Patches memory with NOP instructions (0x90 bytes)
func NopPatch(exeName, addrStr string, numBytes int) error {
	pid, err := findProcessIDByName(exeName)
	if err != nil {
		return err
	}

	baseAddr, err := getModuleBaseAddress(pid, exeName)
	if err != nil {
		return err
	}

	offset, err := parseHexAddr(addrStr)
	if err != nil {
		return err
	}

	addr := baseAddr + offset

	handle, err := windows.OpenProcess(windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	nopBytes := make([]byte, numBytes)
	for i := range nopBytes {
		nopBytes[i] = 0x90
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	var written uintptr
	ret, _, callErr := procWriteProcessMemory.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(&nopBytes[0])),
		uintptr(numBytes),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return callErr
	}
	if written != uintptr(numBytes) {
		return errors.New("failed to write all NOP bytes")
	}

	return nil
}

// Reads a value through a pointer chain
func ReadPointerChain(vt ValueType, exeName, baseAddrStr string, offsets []string) (interface{}, error) {
	pid, err := findProcessIDByName(exeName)
	if err != nil {
		return nil, err
	}

	isWow64, err := isProcess32Bit(pid)
	if err != nil {
		return nil, err
	}

	baseAddr, err := getModuleBaseAddress(pid, exeName)
	if err != nil {
		return nil, err
	}

	initialOffset, err := parseHexAddr(baseAddrStr)
	if err != nil {
		return nil, err
	}

	currentAddr := baseAddr + initialOffset

	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	for i, offsetStr := range offsets[:len(offsets)-1] {
		offset, err := parseHexAddr(offsetStr)
		if err != nil {
			return nil, err
		}

		var bytesRead uintptr
		var ret uintptr
		var callErr error
		if isWow64 {
			var ptr32 uint32
			ret, _, callErr = procReadProcessMemory.Call(
				uintptr(handle),
				currentAddr,
				uintptr(unsafe.Pointer(&ptr32)),
				4,
				uintptr(unsafe.Pointer(&bytesRead)),
			)
			if ret == 0 {
				return nil, fmt.Errorf("ReadProcessMemory failed at step %d (addr: 0x%x): %v", i, currentAddr, callErr)
			}
			if bytesRead != 4 {
				return nil, fmt.Errorf("partial read at step %d (addr: 0x%x): read %d bytes, expected 4", i, currentAddr, bytesRead)
			}
			currentAddr = uintptr(ptr32) + offset
		} else {
			var ptr uintptr
			ret, _, callErr = procReadProcessMemory.Call(
				uintptr(handle),
				currentAddr,
				uintptr(unsafe.Pointer(&ptr)),
				8,
				uintptr(unsafe.Pointer(&bytesRead)),
			)
			if ret == 0 {
				return nil, fmt.Errorf("ReadProcessMemory failed at step %d (addr: 0x%x): %v", i, currentAddr, callErr)
			}
			if bytesRead != 8 {
				return nil, fmt.Errorf("partial read at step %d (addr: 0x%x): read %d bytes, expected 8", i, currentAddr, bytesRead)
			}
			currentAddr = ptr + offset
		}
		_ = i
	}

	finalOffset, err := parseHexAddr(offsets[len(offsets)-1])
	if err != nil {
		return nil, err
	}

	currentAddr += finalOffset

	switch vt {
	case FourBytes:
		var val int32
		var bytesRead uintptr
		ret, _, callErr := procReadProcessMemory.Call(
			uintptr(handle),
			currentAddr,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 {
			return nil, callErr
		}
		if bytesRead != unsafe.Sizeof(val) {
			return nil, errors.New("failed to read all bytes for FourBytes")
		}
		return val, nil
	case Float:
		var val float32
		var bytesRead uintptr
		ret, _, callErr := procReadProcessMemory.Call(
			uintptr(handle),
			currentAddr,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 {
			return nil, callErr
		}
		if bytesRead != unsafe.Sizeof(val) {
			return nil, errors.New("failed to read all bytes for Float")
		}
		return val, nil
	case Double:
		var val float64
		var bytesRead uintptr
		ret, _, callErr := procReadProcessMemory.Call(
			uintptr(handle),
			currentAddr,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 {
			return nil, callErr
		}
		if bytesRead != unsafe.Sizeof(val) {
			return nil, errors.New("failed to read all bytes for Double")
		}
		return val, nil
	default:
		return nil, errors.New("unsupported ValueType")
	}
}

// Changes memory protection flags for a region
func VirtualProtect(exeName, addrStr string, size int, newProtect MemoryProtection) (MemoryProtection, error) {
	pid, err := findProcessIDByName(exeName)
	if err != nil {
		return 0, err
	}

	baseAddr, err := getModuleBaseAddress(pid, exeName)
	if err != nil {
		return 0, err
	}

	offset, err := parseHexAddr(addrStr)
	if err != nil {
		return 0, err
	}

	addr := baseAddr + offset
	handle, err := windows.OpenProcess(windows.PROCESS_VM_OPERATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procVirtualProtect := kernel32.NewProc("VirtualProtect")

	var oldProtect MemoryProtection
	ret, _, callErr := procVirtualProtect.Call(
		addr,
		uintptr(size),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return 0, callErr
	}

	return oldProtect, nil
}

// Conveniently, make some memory writable
func MakeMemoryWritable(exeName, addrStr string, size int) (MemoryProtection, error) {
	return VirtualProtect(exeName, addrStr, size, PAGE_EXECUTE_READWRITE)
}

// Conveniently, restore some memory protection
func RestoreMemoryProtection(exeName, addrStr string, size int, oldProtect MemoryProtection) error {
	_, err := VirtualProtect(exeName, addrStr, size, oldProtect)
	return err
}
