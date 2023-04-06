package common

import (
	bpfgo "github.com/aquasecurity/libbpfgo"
	"strings"
)

const (
	KTracePointType = iota
	KRawTracePointType
	KKprobe
)

type AttachHandle struct {
	AttachType int
	ProgName   string
	EventType  string
}

type AttachPoint struct {
	Handle    AttachHandle
	OwnerProg *bpfgo.BPFProg
}

func (attach *AttachPoint) Attach() error {
	var err error
	if attach.Handle.AttachType == KRawTracePointType {
		_, err = attach.OwnerProg.AttachRawTracepoint(attach.Handle.EventType)
	} else if attach.Handle.AttachType == KKprobe {
		_, err = attach.OwnerProg.AttachKprobe(attach.Handle.EventType)
	} else if attach.Handle.AttachType == KTracePointType {
		dir_and_file := strings.Split(attach.Handle.EventType, "/")
		dir := dir_and_file[0]
		file := dir_and_file[1]
		_, err = attach.OwnerProg.AttachTracepoint(dir, file)
	}
	return err
}
