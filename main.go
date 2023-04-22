package main

import (
	"C"
	"log"
	"main/kstatic"
	"sync"
)

func main() {
	var err error
	var worker *kstatic.KstaticWorker
	wg := sync.WaitGroup{}
	wg.Add(1)
	if worker, err = kstatic.InitKstaticWorker(); err != nil {
		log.Fatalf("InitKstaticWoker error: %v", err)
		return
	}
	log.Printf("begin load symbol values")
	if err = worker.LoadKallsymsValues(); err != nil {
		log.Fatalf("LoadKstaticWorker error: %v", err)
		return
	}
	var addr_map map[string]uint64
	var size_map map[string]uint64
	if addr_map, size_map, err = worker.DumpKallsymsValues(); err != nil {
		log.Fatalf("DumpKallSymbols Value error: %v", err)
		return
	}

	for name, _ := range addr_map {
		log.Printf("Symbol Name: %v, Symbol addr: 0x%016x", name, addr_map[name])
		log.Printf("Symbol Name: %v, Symbol load size: 0x%016x", name, size_map[name])
	}

	if err = worker.DumpGlobals(); err != nil {
		log.Fatalf("DumpGlobals error: %v", err)
	}

	log.Printf("Begin try to load kernel mem......")
	if err = worker.LoadKernelMemory(false); err != nil {
		log.Fatalf("LoadKernelMemory error: %v", err)
	}

	log.Printf("Begin dump the crc hash......")
	if err = worker.DumpMemCrc(); err != nil {
		log.Fatalf("DumpMemCrc error: %v", err)
	}

	worker.StartPollRingBuffer()
	wg.Wait()
}
