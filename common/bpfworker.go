package common

import (
	bpfgo "github.com/aquasecurity/libbpfgo"
	"log"
)

type BpfWorkerCore struct {
	MoudleName  string
	Moudle      *bpfgo.Module
	ProgsMap    map[string]AttachPoint
	MsgRingBufs map[string]*UserRingBuf
	KernelMaps  map[string]*UserHashMap
}

func (core *BpfWorkerCore) setProgPoint(handle AttachHandle) error {
	var err error
	var prog *bpfgo.BPFProg

	if prog, err = core.Moudle.GetProgram(handle.ProgName); err != nil {
		log.Printf("Get Prog %v error: %v", handle.ProgName, err)
		return err
	}
	core.ProgsMap[handle.ProgName] = AttachPoint{
		Handle:    handle,
		OwnerProg: prog,
	}
	return nil
}

func InitWorkercore(mname string, handles []AttachHandle, rbufs []string, maps []string, globals map[string]int32) (*BpfWorkerCore, error) {
	var err error
	core := &BpfWorkerCore{}
	core.MoudleName = mname
	if core.Moudle, err = bpfgo.NewModuleFromFile(GetBpfObjPath(mname)); err != nil {
		return nil, err
	}
	log.Printf("New Moudle From %v ok", mname)

	for global, val := range globals {
		if err = core.Moudle.InitGlobalVariable(global, val); err != nil {
			log.Printf("The err is when Init Global %v: %v", global, err)
			return nil, err
		}
	}

	if err = core.Moudle.BPFLoadObject(); err != nil {
		log.Printf("loadObject error: %v", err)
		return nil, err
	}
	log.Printf("Load BpfObject %v ok", mname)

	core.ProgsMap = make(map[string]AttachPoint)
	handles_len := len(handles)
	for i := 0; i < handles_len; i++ {
		if err = core.setProgPoint(handles[i]); err != nil {
			return nil, err
		}
	}

	for prog, point := range core.ProgsMap {
		if err = point.Attach(); err != nil {
			log.Printf("Attach %v error %v", prog, err)
			return nil, err
		}
	}
	log.Printf("Attach progs ok")

	rbufs_len := len(rbufs)
	core.MsgRingBufs = make(map[string]*UserRingBuf)
	for i := 0; i < rbufs_len; i++ {
		if core.MsgRingBufs[rbufs[i]], err = NewRingBuf(rbufs[i], core.Moudle); err != nil {
			log.Printf("New Ring Buffer %v error: %v", rbufs[i], err)
			return nil, err
		}
	}

	hashmap_len := len(maps)
	core.KernelMaps = make(map[string]*UserHashMap, hashmap_len)
	for i := 0; i < hashmap_len; i++ {
		if core.KernelMaps[maps[i]], err = NewHashMap(maps[i], core.Moudle); err != nil {
			return nil, err
		}
	}

	return core, nil
}
