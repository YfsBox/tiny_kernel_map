package kstatic

import (
	helpers "github.com/aquasecurity/libbpfgo/helpers"
	"kernel_hash/common"
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
		{common.KRawTracePointType, "hello_bpftrace", "sys_enter"},
	}
	rbufs := []string{
		KStaticRingBufName,
	}
	maps := []string{
		KStaticMapName,
	}
	if worker.Core, err = common.InitWorkercore(KernelStaticBpfObjName, handles, rbufs, maps); err != nil {
		return nil, err
	}
	if err = worker.newKernelSymbolsTable(); err != nil {
		return nil, err
	}
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
		key := make([]byte, 10)
		copy(key, ksym_name)
		address := value.Address
		err := kernel_map.Map.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&address))
		if err != nil {
			return err
		}
	}
	return err
}
