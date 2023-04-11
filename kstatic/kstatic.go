package kstatic

import "C"
import (
	"encoding/binary"
	"fmt"
	helpers "github.com/aquasecurity/libbpfgo/helpers"
	"kernel_hash/common"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	KernelStaticBpfObjName = "kernel"
	KStaticRingBufName     = "mrb"
	KStaticMapName         = "kstatic_map"
	KSizeMapName           = "kstatic_size_map"
	KReadBufferMapName     = "read_buffer_map"
	KCrcmapName            = "kernel_crc_map"
	KGlobalValMapName      = "global_val_map"
	MaxKsymNameLen         = 64
	GlobalSymbolOwner      = "system"

	StartExTblIdx = 0
	StopExTblIdx  = 1
	InitTaskIdx   = 2
	SysCallTblIdx = 3
	IdtTbldIdx    = 4

	StartExTableSymbol = "__start___ex_table"
	StopExTableSymbol  = "__stop___ex_table"
	InitTaskSymbol     = "init_task"
	SysCallTableSymbol = "sys_call_table"
	IdtTableSymbol     = "idt_table"

	CurrLoadSysmbolGlobal = "curr_load_sysmbol"
	LoadfdGlobal          = "init_handle_fd"
	UserPidGlobal         = "user_pid"

	LoadKernelMemMsg = "LOAD OK"
)

type KstaticWorker struct {
	Core          *common.BpfWorkerCore
	SymbolNames   []string
	KernelSymbols helpers.KernelSymbolTable
	LoadHandlefd  int
}

type KsymbolMapHandle struct {
	Size uint32
	Addr uint64
}

func eventfd(initval uint64, flags int) (int, error) {
	fd, _, err := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(initval), uintptr(flags), 0)
	if err != 0 {
		return -1, err
	}
	return int(fd), nil
}

func (worker *KstaticWorker) initGlobalValues() (map[string]int32, error) {
	var err error
	globals := make(map[string]int32, 2)
	globals[CurrLoadSysmbolGlobal] = 0
	globals[UserPidGlobal] = int32(os.Getpid())
	if worker.LoadHandlefd, err = eventfd(0, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC); err != nil {
		log.Printf("Create LoadEventfd err: %v", err)
		return nil, err
	}
	globals[LoadfdGlobal] = int32(worker.LoadHandlefd)
	return globals, nil
}

func InitKstaticWorker() (*KstaticWorker, error) {
	var err error
	worker := &KstaticWorker{}

	worker.SymbolNames = []string{
		StartExTableSymbol,
		StopExTableSymbol,
		InitTaskSymbol,
		SysCallTableSymbol,
		IdtTableSymbol,
	}

	handles := []common.AttachHandle{
		{common.KTracePointType, "register_modules", "syscalls/sys_enter_init_module"},
		{common.KTracePointType, "test_ringbuf", "syscalls/sys_enter_execve"},
		{common.KTracePointType, "load_kernel_mem", "syscalls/sys_enter_write"},
	}
	rbufs := []string{
		KStaticRingBufName,
	}
	maps := []string{
		KStaticMapName,
		KSizeMapName,
		KReadBufferMapName,
		KCrcmapName,
		KGlobalValMapName,
	}

	if worker.Core, err = common.InitWorkercore(KernelStaticBpfObjName, handles, rbufs, maps); err != nil {
		log.Printf("InitWorkercoer err: %v", err)
		return nil, err
	}

	if err = worker.newKernelSymbolsTable(); err != nil {
		return nil, err
	}

	var globals_map map[string]int32
	if globals_map, err = worker.initGlobalValues(); err != nil {
		log.Printf("init global values error: %v", err)
		return nil, err
	}

	if err = worker.LoadGlobalValues(globals_map); err != nil {
		return nil, err
	}
	return worker, nil
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

func (ksworker *KstaticWorker) GetSymbolSizeMap() *common.UserHashMap {
	return ksworker.Core.KernelMaps[KSizeMapName]
}

func (ksworker *KstaticWorker) GetGlobalValueMap() *common.UserHashMap {
	return ksworker.Core.KernelMaps[KGlobalValMapName]
}

func (ksworker *KstaticWorker) LoadGlobalValues(globals map[string]int32) error {
	global_map := ksworker.GetGlobalValueMap()
	global_names := []string{
		CurrLoadSysmbolGlobal,
		LoadfdGlobal,
		UserPidGlobal,
	}
	/*for i := 0; i < global_len; i++ {
		key := int32(i)
		value := globals[]
		if err := global_map.Map.Update(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			log.Printf("LoadGlobalValue error in Update: %v", err)
			return err
		}
	}*/
	for i, name := range global_names {
		value := globals[name]
		if err := global_map.Map.Update(unsafe.Pointer(&i), unsafe.Pointer(&value)); err != nil {
			return err
		}
	}
	return nil
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
	kernel_size_map := ksworker.GetSymbolSizeMap()
	symbol_len := len(ksworker.SymbolNames)
	for i := 0; i < symbol_len; i++ {
		key := uint32(i)
		var load_size uint64 = 0
		address := kallsyms_map[ksworker.SymbolNames[i]].Address
		name := ksworker.SymbolNames[i]

		if name == SysCallTableSymbol {
			load_size = 313 * 8
		} else if name == IdtTableSymbol {
			load_size = 4096
		} else if name == StartExTableSymbol {
			load_size = kallsyms_map[StopExTableSymbol].Address - address
		} else if name == InitTaskSymbol {
			load_size = 1972
		}

		err = kernel_map.Map.Update(unsafe.Pointer(&key), unsafe.Pointer(&address))
		if err != nil {
			log.Printf("The err is %v when map.update", err)
			return err
		}
		err = kernel_size_map.Map.Update(unsafe.Pointer(&key), unsafe.Pointer(&load_size))
		if err != nil {
			log.Printf("The err is %v when map.update", err)
			return err
		}
	}
	return err
}

func (ksworker *KstaticWorker) LoadKernelMemory() error {
	if ksworker.LoadHandlefd <= 0 {
		return fmt.Errorf("The Loadhandle fd is not open right")
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(1))

	var rb = ksworker.GetRingBUffer()
	rb.Start()

	var load_time = len(ksworker.SymbolNames)
	for i := 0; i < load_time; {
		if _, err := syscall.Write(ksworker.LoadHandlefd, buf); err != nil {
			return fmt.Errorf("Write to loadHandle error: %v", err)
		}
		select {
		case data := <-rb.Info.BufChan:
			// data_str := string(data)
			/*
				if i == IdtTbldIdx {
					common.PrintIDTTable(data)
				} else {
					common.PrintMemFormat(data)
				}*/
			log.Printf("The hash is %v", common.GetHexHashString(data))
			i++
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}

func (ksworker *KstaticWorker) DumpGlobals() error {
	global_map := ksworker.GetGlobalValueMap()
	for i := 0; i < 3; i++ {
		value, err := global_map.Map.GetValue(unsafe.Pointer(&i))
		if err != nil {
			return err
		}
		val := binary.LittleEndian.Uint32(value)
		log.Printf("the Global index is %v, the value is %v", i, val)
	}
	return nil
}

func (ksworker *KstaticWorker) DumpKallsymsValues() (map[string]uint64, map[string]uint64, error) {
	var err error
	kmap := ksworker.GetKstaticMap()
	ksizemap := ksworker.GetSymbolSizeMap()

	symbols_len := len(ksworker.SymbolNames)
	addr_map := make(map[string]uint64)
	size_map := make(map[string]uint64)
	for i := 0; i < symbols_len; i++ {
		var idx = uint32(i)
		symbol_name := ksworker.SymbolNames[i]
		addr, err := kmap.Map.GetValue(unsafe.Pointer(&idx))
		if err != nil {
			log.Printf("kworker GetValue by key %v from KstaticMap error: %v", symbol_name, err)
			return nil, nil, err
		}

		size, err := ksizemap.Map.GetValue(unsafe.Pointer(&idx))
		if err != nil {
			log.Printf("kworker GetValue by key %v from ksizemap error: %v", symbol_name, err)
			return nil, nil, err
		}

		addr_map[symbol_name] = binary.LittleEndian.Uint64(addr)
		size_map[symbol_name] = binary.LittleEndian.Uint64(size)
	}

	return addr_map, size_map, err
}

func (ksworker *KstaticWorker) GetRingBUffer() *common.UserRingBuf {
	return ksworker.Core.MsgRingBufs[KStaticRingBufName]
}

func (ksworker *KstaticWorker) StartPollRingBuffer() {
	rb := ksworker.GetRingBUffer()
	if !rb.Info.Started {
		rb.Start()
	}
	log.Printf("begin poll ring buffer")
	go func() {
		for {
			select {
			case data := <-rb.Info.BufChan:
				log.Printf("%v", common.GetHexHashString(data))
			}
		}
	}()
}
