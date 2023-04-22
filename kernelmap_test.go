package main

import (
	"log"
	"main/workers"
	"strings"
	"sync"
	"testing"
)

func Test_SplitDirAndFile(t *testing.T) {
	event := "syscalls/sys_enter_open"
	dir_and_file := strings.Split(event, "/")
	dir := dir_and_file[0]
	file := dir_and_file[1]
	if dir != "syscalls" || file != "sys_enter_open" {
		t.Fatalf("spilt err")
	}
}

func Test_InitKstaticWorker(t *testing.T) {
	var err error
	var worker *workers.KstaticWorker
	wg := sync.WaitGroup{}
	wg.Add(1)
	if worker, err = workers.InitKstaticWorker(); err != nil {
		t.Fatalf("InitKstaticWoker error: %v", err)
		return
	}
	log.Printf("begin load symbol values")
	if err = worker.LoadKallsymsValues(); err != nil {
		t.Fatalf("LoadKstaticWorker error: %v", err)
		return
	}
	var addr_map map[string]uint64
	var size_map map[string]uint64
	if addr_map, size_map, err = worker.DumpKallsymsValues(); err != nil {
		t.Fatalf("DumpKallSymbols Value error: %v", err)
		return
	}

	for name, _ := range addr_map {
		log.Printf("Symbol Name: %v, Symbol addr: 0x%016x", name, addr_map[name])
		log.Printf("Symbol Name: %v, Symbol load size: 0x%016x", name, size_map[name])
	}

	if err = worker.DumpGlobals(); err != nil {
		t.Fatalf("DumpGlobals error: %v", err)
	}

	log.Printf("Begin try to load kernel mem......")
	if err = worker.LoadKernelMemory(false); err != nil {
		t.Fatalf("LoadKernelMemory error: %v", err)
	}

	log.Printf("Begin dump the crc hash......")
	if err = worker.DumpMemCrc(); err != nil {
		t.Fatalf("DumpMemCrc error: %v", err)
	}

	worker.StartPollRingBuffer()
	wg.Wait()

}

func Test_RunProcessWorker(t *testing.T) {
	var err error
	// var worker *workers.ProcessWorker
	wg := sync.WaitGroup{}
	wg.Add(1)

	if _, err = workers.InitProcessWorker(); err != nil {
		t.Fatalf("InitProcessWorker error: %v", err)
		return
	}

	wg.Wait()
}
