# Connector eBPF programs

`connector_mark_deny.bpf.c` — `cgroup/skb` egress: drop when `skb->mark` is in `deny_marks`.

```bash
make -C platform/ebpf
connector-kerneld ebpf-load --agent <pid> [--cgroup /sys/fs/cgroup/...]
```

Requires `CAP_BPF` + `CAP_NET_ADMIN`, `bpftool`, and writable bpffs (`/sys/fs/bpf`).
See Seven Pillars P2-T05 / `connector-kerneld` README.
