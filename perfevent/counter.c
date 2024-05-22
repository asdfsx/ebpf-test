//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf.h>
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];
	u8 data[10240];
};

struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
};
struct bpf_map_def SEC("maps/events_stack") events_stack = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event),
    .max_entries = 10000,
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/vfs_open")
int kprobe_vfs_open(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	struct path *path = (struct path *)PT_REGS_PARM1(ctx);

	u32 cpu = 0;
	task_info = bpf_map_lookup_elem(&events_stack, &cpu);
    if (!task_info)
	{
        return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);

	u64 result = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, task_info, sizeof(struct event));
	const char fmt_str[] = "bpf_perf_event_output result %d, pkg_size %d\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), result, sizeof(struct event));

	return 0;
}

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
    u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *ev;

	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    const size_t count = (const size_t)PT_REGS_PARM3(ctx);
    loff_t *pos = (loff_t *)PT_REGS_PARM4(ctx);

    u32 cpu = 0;
	ev = bpf_map_lookup_elem(&events_stack, &cpu);
	
    if (!ev)
	{
        return 0;
	}

	ev->pid = tgid;
	bpf_get_current_comm(&ev->comm, 80);

    if (count > sizeof(ev->data)) {
         bpf_probe_read_user_str(ev->data, sizeof(ev->data), buf);
    } else {
         bpf_probe_read_user_str(ev->data, count, buf);
    }

	long result = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(struct event));
	if (result != 0)
	{
		const char fmt_str[] = "bpf_perf_event_output result 1 %d, pkg_size %d, %d\n";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), result, count, result!=0);
	}
	
	return 0;
}
