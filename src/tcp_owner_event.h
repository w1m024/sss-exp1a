#pragma once

struct tcp_owner_event {
    __u64 start_ns, time_ns;
    __u32 pid, uid;
    __u16 family, local_port, remote_port;
    unsigned char local[16], remote[16];
    char name[16];
};

struct tcp_owner_config { __u64 pidns_dev, pidns_ino; __u32 uid, netns; };
