package workers

import (
	"log"
	"main/common"
)

const (
	ProcessBpfObjName = "process"
)

type ProcessWorker struct {
	Core *common.BpfWorkerCore
}

func InitProcessWorker() (*ProcessWorker, error) {
	var err error
	worker := &ProcessWorker{}
	handles := []common.AttachHandle{
		{common.KKprobe, "measure_on_mmap_region", "mmap_region"},
		{common.KKprobe, "measure_on_mprotect_fixup", "mprotect_fixup"},
		{common.KKprobe, "register_process", "__do_sys_fork"},
	}

	if worker.Core, err = common.InitWorkercore(ProcessBpfObjName, handles, nil, nil); err != nil {
		log.Printf("InitProcessWorker core error: %v", err)
		return nil, err
	}
	return worker, nil
}
