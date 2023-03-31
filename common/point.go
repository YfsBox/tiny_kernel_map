package common

import (
	"fmt"
	bpfgo "github.com/aquasecurity/libbpfgo"
)

const (
	KRawTracePointType = iota
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
	} else {
		err = fmt.Errorf("The Attach is not valid")
	}
	return err
}
