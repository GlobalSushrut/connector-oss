/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Connector OS — cgroup/skb egress mark deny (Seven Pillars §2 / §4).
 * Standalone types (no host asm headers required for -target bpf).
 * Return: 0 = drop, 1 = pass.
 */
#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef long long unsigned int __u64;

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
};

enum bpf_func_id {
	BPF_FUNC_map_lookup_elem = 1,
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
};

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} deny_marks SEC(".maps");

SEC("cgroup_skb/egress")
int connector_mark_deny(struct __sk_buff *skb)
{
	__u32 mark = skb->mark;
	__u8 *deny;

	if (mark == 0)
		return 1;

	deny = bpf_map_lookup_elem(&deny_marks, &mark);
	if (deny && *deny)
		return 0;
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
