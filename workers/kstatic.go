package workers

import "C"
import (
	"encoding/binary"
	"fmt"
	helpers "github.com/aquasecurity/libbpfgo/helpers"
	"log"
	"main/common"
	"os"
	"strings"
	"syscall"
	// "time"
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

	SystemCallTableSize = 323 * 16
	IdtSize             = 4096
	InitTaskSize        = 1972

	StartExTableSymbol = "__start___ex_table"
	StopExTableSymbol  = "__stop___ex_table"
	InitTaskSymbol     = "init_task"
	SysCallTableSymbol = "sys_call_table"
	IdtTableSymbol     = "idt_table"

	CurrLoadSysmbolGlobal = "curr_load_sysmbol"
	LoadfdGlobal          = "init_handle_fd"
	UserPidGlobal         = "user_pid"

	LoadKernelMemMsg = "LOAD OK"
	NotifyMeasureMsg = "BEGIN NOTIFY"
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
		{common.KTracePointType, "register_modules", "module/module_load"},
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

func (ksworker *KstaticWorker) GetCrcHashMap() *common.UserHashMap {
	return ksworker.Core.KernelMaps[KCrcmapName]
}

func (ksworker *KstaticWorker) LoadGlobalValues(globals map[string]int32) error {
	global_map := ksworker.GetGlobalValueMap()
	global_names := []string{
		CurrLoadSysmbolGlobal,
		LoadfdGlobal,
		UserPidGlobal,
	}
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
			load_size = SystemCallTableSize
		} else if name == IdtTableSymbol {
			load_size = IdtSize
		} else if name == StartExTableSymbol {
			load_size = kallsyms_map[StopExTableSymbol].Address - address
		} else if name == InitTaskSymbol {
			load_size = InitTaskSize
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

func (ksworker *KstaticWorker) LoadKernelMemory(inited bool) error {
	if ksworker.LoadHandlefd <= 0 {
		return fmt.Errorf("The Loadhandle fd is not open right")
	}
	wbuf := make([]byte, 8)
	rbuf := make([]byte, 8)
	if inited {
		for i := range wbuf {
			wbuf[i] = 0xf
		}
	}

	var rb = ksworker.GetRingBUffer()
	rb.Start()
	var load_time = len(ksworker.SymbolNames)
	// time.Sleep(500 * time.Millisecond)
	for i := 0; i < load_time; i++ {
		if _, err := syscall.Write(ksworker.LoadHandlefd, wbuf); err != nil {
			return fmt.Errorf("Write to loadHandle error: %v", err)
		}
		syscall.Read(ksworker.LoadHandlefd, rbuf)
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

func (ksworker *KstaticWorker) DumpMemCrc() error {
	crc_map := ksworker.GetCrcHashMap()
	kernel_num := len(ksworker.SymbolNames)
	for i := 0; i < kernel_num; i++ {
		if ksworker.SymbolNames[i] == StopExTableSymbol {
			continue
		}
		value, err := crc_map.Map.GetValue(unsafe.Pointer(&i))
		if err != nil {
			return err
		}
		val := binary.LittleEndian.Uint64(value)
		log.Printf("The crc hash of %v is %v", ksworker.SymbolNames[i], val)
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

	for {
		select {
		case data := <-rb.Info.BufChan:
			msg := string(data)
			if strings.Contains(msg, NotifyMeasureMsg) {
				log.Printf("begin measure from ebpf")
				go func() {
					if err := ksworker.LoadKernelMemory(true); err != nil {
						log.Printf("Measure Memory error: %v", err)
					}
				}()
			} else {
				log.Printf("Get Message from ebpf: %v", msg)
			}
		}
	}
}
