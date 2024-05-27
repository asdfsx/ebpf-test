//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf.h>
#include <linux/limits.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];
	u8 filename[101];
    u8 fn_name[101];
    __s32 lineno;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

//https://github.com/mmat11/usdt/blob/main/examples/python_builtin/bpf/py_builtin.c
SEC("uprobe/python/function__entry")
int uprobe_python_function_entry(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;

	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);
	bpf_probe_read_user_str(task_info->filename, 101, (void *)ctx->r14);
    bpf_probe_read_user_str(task_info->fn_name, 101, (void *)ctx->r15);
    task_info->lineno = ctx->ax;
	
	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

SEC("uprobe/python/function__return")
int uprobe_python_function_return(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);
	bpf_probe_read_user_str(task_info->filename, 101, (void *)ctx->r14);
    bpf_probe_read_user_str(task_info->fn_name, 101, (void *)ctx->r15);
    task_info->lineno = ctx->ax;

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
