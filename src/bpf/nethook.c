#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Structure to store network hook data
struct net_hook_data {
    u64 packets;
    u64 bytes;
    u64 errors;
};

// Function to parse network packet metadata
static inline int parse_metadata(const void *data, int offset, struct bpf_md *ctx) {
    // Parse Ethernet header
    struct eth_hdr *eth = data + offset;
    ctx->net_hdr = (void *)data;

    // Parse IP header
    struct ip_hdr *ip = (struct ip_hdr *)((u8 *)eth + sizeof(*eth));
    ctx->src_ip = ip->saddr;
    ctx->dst_ip = ip->daddr;

    // Parse TCP/UDP header
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((u8 *)ip + sizeof(*ip));
        ctx->proto = IPPROTO_TCP;
        ctx->src_port = ntohs(tcp->source);
        ctx->dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((u8 *)ip + sizeof(*ip));
        ctx->proto = IPPROTO_UDP;
        ctx->src_port = ntohs(udp->source);
        ctx->dst_port = ntohs(udp->dest);
    }

    return sizeof(*eth) + sizeof(*ip);
}

// eBPF program that handles network hook
static void __always_inline bpf_program(struct bpf_md *ctx, struct net_hook_data *data) {
    // Get the packet metadata
    int offset = parse_metadata(ctx->net_hdr, 0, ctx);
    u32 packet_len = offset + sizeof(struct eth_hdr) + sizeof(struct ip_hdr);

    // Update packet statistics
    atomic_add(&data->packets, 1);
    atomic_add(&data->bytes, packet_len);

    // Handle errors (e.g., packet drops)
    if (ctx->err == 1) {
        atomic_add(&data->errors, 1);
    }
}

// eBPF map to store network hook data
static void __always_inline bpf_map_init(void *map, u32 key_size, u32 value_size) {
    bpf_map_update_elem(map, &key_size, &value_size, BPF_NOEXIST);
}

// eBPF program entry point
static void __always_inline bpf_main(struct bpf_md *ctx, struct net_hook_data *data) {
    bpf_program(ctx, data);
}

// eBPF program that initializes network hook data
static void __always_inline bpf_init(void *map, struct net_hook_data *data) {
    bpf_map_init(map, sizeof(u64), sizeof(u64));
    memset(data, 0, sizeof(*data));
}

// eBPF program that loads and initializes network hook data
static void __always_inline bpf_load(struct bpf_md *ctx, void *map, struct net_hook_data *data) {
    bpf_init(map, data);
}
```

```c
// License and copyright information
// Licensed under the terms of the MIT License
// Copyright (c) [Year] [Author]

// BPF program that loads network hook data
static void __always_inline bpf_load_net_hook(void *map) {
    struct net_hook_data data;
    bpf_load(map, &data);
}
```

```c
// BPF program that initializes network hook data
static void __always_inline bpf_init_net_hook(void *map) {
    struct net_hook_data data;
    bpf_init(map, &data);
}
```

```c
// BPF program that handles network hook
static void __always_inline bpf_net_hook(struct bpf_md *ctx, void *map) {
    struct net_hook_data data;
    bpf_load_net_hook(map);
    bpf_main(ctx, &data);
}
```

```c
// BPF map to store network hook data
static void __always_inline bpf_map_net_hook(void *map) {
    bpf_map_init(map, sizeof(u64), sizeof(u64));
}
```

```c
// BPF program that loads network hook data from BPF map
static void __always_inline bpf_load_net_hook_map(void *map) {
    struct net_hook_data data;
    bpf_load(map, &data);
}