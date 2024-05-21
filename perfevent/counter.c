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
	u8 data[10240];
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, struct event);
// 	__uint(max_entries, 10000);
// } events_stack SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// 	__uint(max_entries, 1 << 24);
// } events SEC(".maps");

struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
};
struct bpf_map_def SEC("maps/events_stack") events_stack = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event),
    .max_entries = 10000,
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
    u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
    struct event *ev;
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);

	const char fmt_str1[] = "bpf_perf_event_output result\n";
    bpf_trace_printk(fmt_str1, sizeof(fmt_str1));

    u32 cpu = 0;
	ev = bpf_map_lookup_elem(&events_stack, &cpu);
    if (!ev)
	{
		const char fmt_str[] = "bpf_map_lookup_elem result %d, pkg_size %d\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), ev, sizeof(struct event));
        return 0;
	}

	ev->pid = tgid;
	bpf_get_current_comm(&ev->comm, 80);

	u64 result = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(struct event));
	const char fmt_str[] = "bpf_perf_event_output result %d, pkg_size %d\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), result, sizeof(struct event));

	return 0;
}
