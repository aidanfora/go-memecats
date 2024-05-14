package main

//
//go:generate go run packer/packer.go -o stub
//go:generate go build -o stub/stub github.com/aidanfora/go-memecats/stub
//go:generate go run fixer/fixer.go -s stub/stub -o go-memecats.exe
