package memory

import (
	"encoding/hex"
	"errors"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Parse some hexadecimal address.
func parseHexAddr(s string) (uintptr, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
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

type ValueType int

const (
	FourBytes ValueType = iota
	Float
	Double
)

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

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	switch vt {
	case FourBytes:
		var val int32
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

	var dataPtr unsafe.Pointer
	var dataSize uintptr

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

	return nil
}

func FreezeValue(vt ValueType, exeName, addrStr string, value interface{}) error {
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
			procWriteProcessMemory.Call(
				uintptr(handle),
				addr,
				uintptr(dataPtr),
				dataSize,
				uintptr(unsafe.Pointer(&written)),
			)

			time.Sleep(100 * time.Millisecond)
		}
	}()

	return nil
}
