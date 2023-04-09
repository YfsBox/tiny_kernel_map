package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

const (
	BpfObjPathPrefix = "./build/bpfs/"
	BpfObjSuffix     = ".bpf.o"
)

var DebugOn = true

func DPrintf(format string, args ...any) {
	if DebugOn == true {
		log.Printf(format, args)
	}
}

func GetBpfObjName(name string) string {
	return name + BpfObjSuffix
}

func GetBpfObjPath(name string) string {
	return BpfObjPathPrefix + GetBpfObjName(name)
}

func DumpBytes(data []byte) {
	for i := 0; i < len(data); i += 8 {
		end := i + 8
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("%08x: %-16x %s\n", i, data[i:end], Printable(data[i:end]))
	}
}

func Printable(data []byte) string {
	result := ""
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			result += string(b)
		} else {
			result += "."
		}
	}
	return result
}

func PrintIDTTable(idt []byte) {
	const idtEntrySize = 16 // idt表项的大小是16字节
	numEntries := len(idt) / idtEntrySize
	for i := 0; i < numEntries; i++ {
		offset := i * idtEntrySize
		entry := idt[offset : offset+idtEntrySize]
		var addr uint64
		var selector uint16
		binary.Read(bytes.NewReader(entry[:8]), binary.LittleEndian, &addr)
		binary.Read(bytes.NewReader(entry[8:10]), binary.LittleEndian, &selector)
		fmt.Printf("IDT[%d]: addr=0x%x, selector=0x%x\n", i, addr, selector)
	}
}

func PrintMemFormat(syscallTable []byte) {
	// fmt.Println("System call table:")
	for i := 0; i < len(syscallTable); i += 8 {
		end := i + 8
		if end > len(syscallTable) {
			end = len(syscallTable)
		}
		fmt.Printf("%08x: %-48x %s\n", i, syscallTable[i:end], Printable(syscallTable[i:end]))
	}
}

func GetHexHashString(hash []byte) string {
	hash_len := len(hash)
	var str string
	for i := 0; i < hash_len; i++ {
		str += fmt.Sprintf("%02x", hash[i])
	}
	return str
}
