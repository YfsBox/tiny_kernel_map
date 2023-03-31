package kernel_hash

import (
	"kernel_hash/kstatic"
	"log"
	"testing"
)

func Test_InitKstaticWorker(t *testing.T) {
	var err error
	var worker *kstatic.KstaticWorker
	symbols := []string{
		"__start___ex_table",
		"__stop___ex_table",
		"init_task",
		"sys_call_table",
	}
	if worker, err = kstatic.InitKstaticWorker(symbols); err != nil {
		t.Fatalf("InitKstaticWoker error: %v", err)
		return
	}
	log.Printf("begin load symbol values")
	if err = worker.LoadKallsymsValues(); err != nil {
		t.Fatalf("LoadKstaticWorker error: %v", err)
		return
	}
	var values_map map[string]uint64
	if values_map, err = worker.DumpKallsymsValues(); err != nil {
		t.Fatalf("DumpKallSymbols Value error: %v", err)
		return
	}

	for name, addr := range values_map {
		t.Logf("Symbol Name: %v, Symbol addr: 0x%016x", name, addr)
	}
}
