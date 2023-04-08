package common

import bpfgo "github.com/aquasecurity/libbpfgo"

const (
	KDefaultChanSize = 300
	KDefaultPageCnt  = 1024
)

type BpfMapInfo struct {
	Started bool
	Name    string
	Owner   *bpfgo.Module
	BufChan chan []byte
}

type UserRingBuf struct {
	Info    BpfMapInfo
	RingBuf *bpfgo.RingBuffer
}

type UserPerfBuf struct {
	Info    BpfMapInfo
	PerfBuf *bpfgo.PerfBuffer
}

type UserHashMap struct {
	Info BpfMapInfo
	Map  *bpfgo.BPFMap
}

func NewPerfBuf(name string, owner *bpfgo.Module) (*UserPerfBuf, error) {
	var err error
	upbuf := &UserPerfBuf{
		Info: BpfMapInfo{
			false, name, owner, make(chan []byte, KDefaultChanSize),
		},
	}
	if upbuf.PerfBuf, err = owner.InitPerfBuf(name, upbuf.Info.BufChan, nil, KDefaultPageCnt); err != nil {
		DPrintf("InitPerbuf %v error: %v", name, err)
		return nil, err
	}
	return upbuf, nil
}

func NewRingBuf(name string, owner *bpfgo.Module) (*UserRingBuf, error) {
	var err error
	urbuf := &UserRingBuf{
		Info: BpfMapInfo{
			false, name, owner, make(chan []byte),
		},
	}
	if urbuf.RingBuf, err = owner.InitRingBuf(name, urbuf.Info.BufChan); err != nil {
		DPrintf("InitRingBuf %v error %v", name, err)
		return nil, err
	}
	return urbuf, nil
}

func NewHashMap(name string, owner *bpfgo.Module) (*UserHashMap, error) {
	var err error
	hashmap := &UserHashMap{
		Info: BpfMapInfo{
			false, name, owner, nil,
		},
	}
	if hashmap.Map, err = owner.GetMap(name); err != nil {
		return nil, err
	}
	return hashmap, nil
}

func (rbuf *UserRingBuf) Start() {
	rbuf.Info.Started = true
	rbuf.RingBuf.Start()
}

func (rbuf *UserRingBuf) Close() {
	rbuf.Info.Started = false
	close(rbuf.Info.BufChan)
	rbuf.RingBuf.Stop()
	rbuf.RingBuf.Close()
}

func (pbuf *UserPerfBuf) Start() {
	pbuf.Info.Started = true
	pbuf.PerfBuf.Start()
}

func (pbuf *UserPerfBuf) Close() {
	pbuf.Info.Started = false
	close(pbuf.Info.BufChan)
	pbuf.PerfBuf.Stop()
	pbuf.PerfBuf.Close()
}
