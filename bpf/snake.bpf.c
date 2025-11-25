#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} execve_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} file_ops_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} network_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} process_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} context_switch_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} event_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u64);
    __type(value, __u64);
} recent_events SEC(".maps");

static void update_event_rate(void)
{
    __u64 current_time = bpf_ktime_get_ns() / 1000000000;
    __u32 key = 0;
    __u64 *rate = bpf_map_lookup_elem(&event_rate, &key);
    if (rate) {
        __u64 *count = bpf_map_lookup_elem(&recent_events, &current_time);
        if (count) {
            *rate = *count;
        } else {
            *rate = 0;
        }
    }
    
    __u64 old_time = current_time - 10;
    bpf_map_delete_elem(&recent_events, &old_time);
}

static void increment_event_bucket(void)
{
    __u64 current_time = bpf_ktime_get_ns() / 1000000000;
    __u64 *count = bpf_map_lookup_elem(&recent_events, &current_time);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&recent_events, &current_time, &initial, BPF_ANY);
    }
}

SEC("kprobe/sys_enter_execve")
int handle_execve(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&execve_counter, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        increment_event_bucket();
        update_event_rate();
    }
    return 0;
}

SEC("kprobe/do_sys_openat2")
int handle_file_open(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&file_ops_counter, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        increment_event_bucket();
    }
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int handle_network_connect(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&network_counter, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        increment_event_bucket();
    }
    return 0;
}

SEC("kprobe/_do_fork")
int handle_process_fork(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&process_counter, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        increment_event_bucket();
    }
    return 0;
}

SEC("kprobe/__schedule")
int handle_context_switch(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&context_switch_counter, &key);
    if (value) {
        if (*value % 100 == 0) {
            __sync_fetch_and_add(value, 100);
        } else {
            __sync_fetch_and_add(value, 1);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
