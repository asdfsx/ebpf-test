//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf.h>
#include <linux/limits.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u64 syscall_id;
	u8 comm[80];
	u8 data[32760];
};

struct syscalls_enter_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

    long id;
    unsigned long args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));


SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs;
    regs = (struct pt_regs *) ctx->args[0];
    unsigned long syscall_id = ctx->args[1];  

	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);
	task_info->syscall_id = syscall_id;

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
