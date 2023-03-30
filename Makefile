ARCH=$(shell uname -m)

TARGET := kernelhash
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SRC := *.bpf.c

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib64/libbpf.a

.PHONY: all
bpf: $(TARGET_BPF)
main: $(TARGET)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET)

$(TARGET_BPF): $(BPF_SRC)
	./build.sh
	cd build
	make

.PHONY: clean
clean:
	rm $(TARGET_BPF)
	rm $(TARGET)