package main

//
//go:generate go run -ldflags "-s" packer/packer.go -o stub
//go:generate go build -o go-memecats.exe -ldflags "-s" github.com/aidanfora/go-memecats/stub
