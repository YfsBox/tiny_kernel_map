ARCH=$(shell uname -m)

TARGET := kernelhash
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SRC := *.bpf.c

LIBBPF_HEADERS := bpfs/libbpf/src
LIBBPF_OBJ := build/bpfs/libbpf/libbpf.a

.PHONY: all
bpf: $(TARGET_BPF)
main: $(TARGET)
test:
	$(go_env) go test -v

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET)

$(TARGET_BPF): $(BPF_SRC)
	./build.sh
	cd build
	make

.PHONY: clean
clean:
	rm $(TARGET)