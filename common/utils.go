package common

import "log"

const (
	BpfObjPathPrefix = "./build/bpfs/"
	BpfObjSuffix     = ".bpf.o"
)

var DebugOn bool

func DPrintf(format string, args ...any) {
	if DebugOn {
		log.Printf(format, args)
	}
}

func GetBpfObjName(name string) string {
	return name + BpfObjSuffix
}

func GetBpfObjPath(name string) string {
	return BpfObjPathPrefix + GetBpfObjName(name)
}
