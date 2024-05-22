package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate bpf2go -cc clang-17 -target amd64 -type event bpf counter.c -- -I../headers

func main() {
	syscallTable, err := GetSyscallTable()
	if err != nil {
		log.Fatal(err)
	}

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will emit an event containing pid and command of the execved task.
	link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.TraceSysEnter,
	})
	if err != nil {
		log.Fatalf(("attach failed"))
	}
	defer link.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// bpfEvent is generated by bpf2go.
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		if event.Pid != uint32(841027) {
			continue
		}

		syscallName := syscallTable[event.SyscallId]

		log.Printf("pid: %d\tcomm: %s\tsyscall_id:%d\tsyscall_name:%s\n", event.Pid, unix.ByteSliceToString(event.Comm[:]), event.SyscallId, syscallName)
	}
}

func GetSyscallTable() (map[uint64]string, error) {
	result := map[uint64]string{}
	headfile := "/usr/include/asm/unistd_64.h"
	prefix := "#define __NR_"
	prefixLength := len(prefix)

	f, err := os.Open(headfile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, prefix) {
			tmp := strings.Split(line[prefixLength:], " ")
			id, err := strconv.ParseUint(tmp[1], 10, 64)
			if err != nil {
				log.Printf("failed to parse syscallid %s: %s\n", tmp[1], tmp[0])
				continue
			}
			result[id] = tmp[0]
		}
	}
	return result, nil
}
