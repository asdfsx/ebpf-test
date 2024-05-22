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
	u8 data[32760];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/vfs_open")
int kprobe_execve(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	struct path *path = (struct path *)PT_REGS_PARM1(ctx);

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t *pos = (loff_t *)PT_REGS_PARM4(ctx);

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);

	if (count > sizeof(task_info->data)) {
         bpf_probe_read_user_str(task_info->data, sizeof(task_info->data), buf);
    } else {
         bpf_probe_read_user_str(task_info->data, count, buf);
    }

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
