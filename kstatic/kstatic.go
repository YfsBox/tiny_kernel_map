package kstatic

import (
	"encoding/binary"
	helpers "github.com/aquasecurity/libbpfgo/helpers"
	"kernel_hash/common"
	"log"
	"unsafe"
)

const (
	KernelStaticBpfObjName = "kernel"
	KStaticRingBufName     = "mrb"
	KStaticMapName         = "kstatic_map"
	MaxKsymNameLen         = 64
	GlobalSymbolOwner      = "system"
)

type KstaticWorker struct {
	Core          *common.BpfWorkerCore
	SymbolNames   []string
	KernelSymbols helpers.KernelSymbolTable
}

func InitKstaticWorker(symbols []string) (*KstaticWorker, error) {
	var err error
	worker := &KstaticWorker{}
	handles := []common.AttachHandle{
		{common.KTracePointType, "register_modules", "syscalls/sys_enter_init_module"},
		{common.KTracePointType, "test_ringbuf", "syscalls/sys_enter_execve"},
	}
	rbufs := []string{
		KStaticRingBufName,
	}
	maps := []string{
		KStaticMapName,
	}
	if worker.Core, err = common.InitWorkercore(KernelStaticBpfObjName, handles, rbufs, maps); err != nil {
		log.Printf("InitWorkercoer err: %v", err)
		return nil, err
	}
	if err = worker.newKernelSymbolsTable(); err != nil {
		return nil, err
	}
	worker.SymbolNames = make([]string, len(symbols))
	copy(worker.SymbolNames, symbols)
	return worker, err
}

func (ksworker *KstaticWorker) newKernelSymbolsTable() error {
	var err error
	if ksworker.KernelSymbols, err = helpers.NewKernelSymbolsMap(); err != nil {
		return err
	}
	return nil
}

func (ksworker *KstaticWorker) GetKstaticMap() *common.UserHashMap {
	return ksworker.Core.KernelMaps[KStaticMapName]
}

// 根据目标符号名，获取到其中的符号信息，返回该map
func (ksworker *KstaticWorker) LoadKallsymsValues() error {
	var err error
	kallsyms_map := make(map[string]*helpers.KernelSymbol)
	for _, name := range ksworker.SymbolNames {
		symbol, err := ksworker.KernelSymbols.GetSymbolByName(GlobalSymbolOwner, name)
		if err == nil {
			kallsyms_map[name] = symbol
		}
	}
	kernel_map := ksworker.GetKstaticMap()
	for ksym_name, value := range kallsyms_map {
		key := make([]byte, 64)
		copy(key, ksym_name)
		address := value.Address
		err := kernel_map.Map.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&address))
		if err != nil {
			return err
		}
	}
	return err
}

func (ksworker *KstaticWorker) DumpKallsymsValues() (map[string]uint64, error) {
	var err error
	kmap := ksworker.GetKstaticMap()
	symbols_len := len(ksworker.SymbolNames)
	values_map := make(map[string]uint64)
	for i := 0; i < symbols_len; i++ {
		name := make([]byte, 64)
		symbol_name := ksworker.SymbolNames[i]
		copy(name, symbol_name)
		value, err := kmap.Map.GetValue(unsafe.Pointer(&name[0]))
		if err != nil {
			log.Printf("kworker GetValue by key %v from KstaticMap error: %v", symbol_name, err)
			return nil, err
		}
		values_map[symbol_name] = binary.LittleEndian.Uint64(value)
	}
	return values_map, err
}

func (ksworker *KstaticWorker) GetRingBUffer() *common.UserRingBuf {
	return ksworker.Core.MsgRingBufs[KStaticRingBufName]
}

func (ksworker *KstaticWorker) StartPollRingBuffer() {
	rb := ksworker.GetRingBUffer()
	log.Printf("begin poll ring buffer")
	for {
		select {
		case data := <-rb.Info.BufChan:
			data_str := string(data)
			log.Printf("%v", data_str)
		}
	}
}
