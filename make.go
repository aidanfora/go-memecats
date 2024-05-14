package main

//
//go:generate go run -ldflags "-s" packer/packer.go -o stub
//go:generate go build -o stub/stub -ldflags "-s" github.com/aidanfora/go-memecats/stub
//go:generate go run -ldflags "-s" fixer/fixer.go -s stub/stub -o go-memecats.exe
