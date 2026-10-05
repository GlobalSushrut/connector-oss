/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Connector OS — cgroup/connect4 transparent redirect to Connector egress proxy (T2).
 * Rewrites userspace connect() destinations to proxy_ip:proxy_port when
 * force_proxy map value is non-zero (or always when map key 0 is set).
 *
 * Return: 1 = allow (possibly rewritten), 0 = deny.
 */
#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
};

enum bpf_func_id {
	BPF_FUNC_map_lookup_elem = 1,
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port; /* network byte order */
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	__u32 __pad0;
};

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;

/* key 0: force_proxy (u8). key 1 unused. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} proxy_cfg SEC(".maps");

/* value layout when key=0: low 8 bits = force (1=on)
 * key=1: proxy IPv4 (host order)
 * key=2: proxy port (host order)
 */

SEC("cgroup/connect4")
int connector_connect_redirect(struct bpf_sock_addr *ctx)
{
	__u32 k0 = 0, k1 = 1, k2 = 2;
	__u32 *force;
	__u32 *pip;
	__u32 *pport;

	force = bpf_map_lookup_elem(&proxy_cfg, &k0);
	if (!force || (*force & 0xff) == 0)
		return 1;

	pip = bpf_map_lookup_elem(&proxy_cfg, &k1);
	pport = bpf_map_lookup_elem(&proxy_cfg, &k2);
	if (!pip || !pport || *pport == 0)
		return 1;

	/* Do not redirect loopback→loopback to the same proxy (avoid loops). */
	if (ctx->user_ip4 == __builtin_bswap32(0x7f000001) /* 127.0.0.1 nbo */) {
		__u16 sport = (__u16)(__builtin_bswap32(ctx->user_port) >> 16);
		if (sport == (__u16)(*pport))
			return 1;
	}

	ctx->user_ip4 = __builtin_bswap32(*pip);
	/* user_port is network-order port in lower 16 bits of the u32 field */
	ctx->user_port = (__u32)__builtin_bswap16((__u16)(*pport));
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
