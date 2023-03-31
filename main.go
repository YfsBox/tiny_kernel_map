package main

import (
	"C"
	"fmt"
	bpfgo "github.com/aquasecurity/libbpfgo"
	"log"
	"os"
)

const sys_execve = "__x64_sys_execve"

func AssertError(err error) {
	if err != nil {
		log.Printf("%v", err)
		os.Exit(0)
	}
}

func main() {
	pwd, _ := os.Getwd()
	log.Printf("curr path is %v\n", pwd)
	bpfModule, err := bpfgo.NewModuleFromFile("/root/bpf_project/kernel_hashmap/build/bpfs/kernel.bpf.o")
	AssertError(err)
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	AssertError(err)
	prog, err := bpfModule.GetProgram("hello_bpftrace")
	AssertError(err)
	_, err = prog.AttachRawTracepoint("sys_enter")
	AssertError(err)

	event_channel := make(chan []byte, 300)
	defer close(event_channel)
	log.Printf("begin Init ring buf")

	ringbuf, err := bpfModule.InitRingBuf("mrb", event_channel)
	AssertError(err)
	defer ringbuf.Close()

	go func() {
		for event_data := range event_channel {
			comm := string(event_data)
			log.Printf("%v", comm)
		}
	}()

	fmt.Println("Cleaning up")
}
