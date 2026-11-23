#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct in6_addr { unsigned char bytes[16]; };
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
typedef struct { struct net *net; } possible_net_t;

struct sock_common {
    __u32 skc_daddr, skc_rcv_saddr;
    __u16 skc_dport, skc_num, skc_family;
    struct in6_addr skc_v6_daddr, skc_v6_rcv_saddr;
    possible_net_t skc_net;
} __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
} __attribute__((preserve_access_index));

#include "tcp_owner_event.h"

// 旧版 libbpf 头文件未声明 bpf_get_func_ret，使用 Linux UAPI 的固定编号。
static long (*read_return_value)(void *, __u64 *) = (void *)184;
const volatile struct tcp_owner_config config = {};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int emit(struct sock *sk) {
    __u32 uid = bpf_get_current_uid_gid();
    if (!sk || uid != config.uid || BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) != config.netns) return 0;
    struct tcp_owner_event e = {};
    e.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (e.family == 2) {
        bpf_core_read(e.local, 4, &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(e.remote, 4, &sk->__sk_common.skc_daddr);
    } else if (e.family == 10) {
        bpf_core_read(e.local, 16, &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(e.remote, 16, &sk->__sk_common.skc_v6_daddr);
    } else return 0;
    e.local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e.remote_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (!e.local_port || !e.remote_port) return 0;
    e.uid = uid;
    struct bpf_pidns_info pid = {};
    if (bpf_get_ns_current_pid_tgid(config.pidns_dev, config.pidns_ino, &pid, sizeof(pid))) return 0;
    e.pid = pid.tgid;
    struct task_struct *task = (void *)bpf_get_current_task();
    e.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e.time_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e.name, sizeof(e.name));
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}

// 在内核分配本地地址和端口后记录套接字。
SEC("fexit/tcp_v4_connect")
int connect4(__u64 *ctx) {
    __u64 result = 0;
    if (read_return_value(ctx, &result) || (int)result) return 0;
    return emit((void *)ctx[0]);
}
SEC("fexit/tcp_v6_connect")
int connect6(__u64 *ctx) {
    __u64 result = 0;
    if (read_return_value(ctx, &result) || (int)result) return 0;
    return emit((void *)ctx[0]);
}
SEC("fexit/inet_csk_accept")
int accept_tcp(__u64 *ctx) {
    __u64 result = 0;
    if (read_return_value(ctx, &result)) return 0;
    return emit((void *)result);
}
char LICENSE[] SEC("license") = "GPL";
