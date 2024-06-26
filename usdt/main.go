package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mmat11/usdt"
	"golang.org/x/sys/unix"
)

//go:generate bpf2go -cc clang-17 -target amd64 -type event bpf counter.c -- -I../headers

func main() {
	var pid uint64
	flag.Uint64Var(&pid, "pid", 0, "要跟踪的pid")

	flag.Parse()

	var err error
	// selfPid := os.Getpid()

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	var spec *ebpf.CollectionSpec
	if spec, err = loadBpf(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open Executable on the tracee PID.
	u, err := usdt.New(objs.UprobePythonFunctionEntry, "python", "function__entry", int(pid))
	if err != nil {
		log.Fatalf("open usdt: %v", err)
	}
	defer u.Close()

	// u, err := usdt.New(objs.UprobePythonFunctionEntry, "python", "function__entry", selfPid)
	// if err != nil {
	// 	log.Fatalf("open usdt: %v", err)
	// }
	// defer u.Close()

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

		log.Printf("pid: %d\tcomm: %s\tfile: %s\tfunc: %s\tlineno: %d\n",
			event.Pid, unix.ByteSliceToString(event.Comm[:]),
			unix.ByteSliceToString(event.Filename[:]),
			unix.ByteSliceToString(event.FnName[:]),
			event.Lineno,
		)
	}
}
