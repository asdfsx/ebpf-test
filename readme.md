# Test Enviroment

```
OS            Ubuntu 22.04
Kernal        Linux 6.5.0-35-generic
Clang         clang version 17.0.6
cilium/ebpf   v0.15.0
```

# ringbuf version

```
cd ringbuf
go generate
go build
./ringbuf
```

ringbuf version can be built and run successfully.

# perf event version

```
cd perfevenbt
go generate
go build
./perfevent
#strace -f -ebpf -o strace_output.txt ./perfevent 1> stdout.txt 2> stderr.txt
```

perfevent version can be build successfully.  
When `event.data` is `u8 data[1024]` the program can execute few error output `event ring buffer full, dropped 4 samples`.  
When `event.data` is `u8 data[10240]` the program stucked.
