package kstatic

import "C"
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

	StartExTblIdx = 0
	StopExTblIdx  = 1
	InitTaskIdx   = 2
	SysCallTblIdx = 3
	IdtTbldIdx    = 4
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
	symbol_len := len(ksworker.SymbolNames)
	for i := 0; i < symbol_len; i++ {
		key := uint32(i)
		address := kallsyms_map[ksworker.SymbolNames[i]].Address
		err := kernel_map.Map.Update(unsafe.Pointer(&key), unsafe.Pointer(&address))
		if err != nil {
			log.Printf("The err is %v when map.update", err)
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
		var idx = uint32(i)
		symbol_name := ksworker.SymbolNames[i]
		value, err := kmap.Map.GetValue(unsafe.Pointer(&idx))
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
	rb.Start()
	log.Printf("begin poll ring buffer")
	go func() {
		for {
			select {
			case data := <-rb.Info.BufChan:
				data_str := string(data)
				log.Printf("%v", data_str)
			}
		}
	}()
}

func (ksworker *KstaticWorker) ReadFromSystbl() {

}
