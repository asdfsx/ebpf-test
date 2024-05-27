module ebpf-test

go 1.22.2

require (
	github.com/cilium/ebpf v0.15.0
	github.com/mmat11/usdt v0.0.0
	golang.org/x/sys v0.15.0
)

require golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect

replace github.com/mmat11/usdt => github.com/asdfsx/usdt v0.0.0-20240524072822-e9bf70a3453b
