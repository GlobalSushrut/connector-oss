"""Demo 1 — Hello World  (5 capabilities, YAML config)

Run:  export OPENAI_API_KEY=sk-...  &&  python demos/python/01_hello_world.py
"""
from vac_ffi import Connector
import os

# ── load from YAML (env-var interpolated by Rust kernel) ─────────────────────
c = Connector.from_config(os.path.join(os.path.dirname(__file__), "hello.yaml"))
print(repr(c), "\n")

# 1. Agent execution ──────────────────────────────────────────────────────────
agent  = c.agent("bot", "You are a concise assistant.")
result = agent.run("What is 2+2? One sentence.", "user:alice")
print(f"[1] text={result.text!r}  trust={result.trust}/100  grade={result.trust_grade}  ok={result.ok}")

# 2. Kernel memory ────────────────────────────────────────────────────────────
before = c.packet_count()
agent.run("Capital of France?", "user:alice")
agent.run("Name three planets.", "user:alice")
print(f"[2] packets: {before} → {c.packet_count()}  audit_entries={c.audit_count()}")

# 3. CID provenance ───────────────────────────────────────────────────────────
pid  = c.register_agent("prover")
cid1 = c.write_packet(pid, "fever 38.5C", "user:alice", "pipe:demo")
cid2 = c.write_packet(pid, "fever 38.5C", "user:alice", "pipe:demo")  # same → same CID
cid3 = c.write_packet(pid, "cough",       "user:alice", "pipe:demo")  # diff  → diff CID
print(f"[3] same_content_same_cid={cid1==cid2}  diff_content_diff_cid={cid1!=cid3}")
print(f"    cid={cid1}")

# 4. Namespace isolation ──────────────────────────────────────────────────────
a = c.agent("alice", "Help Alice."); a.run("Alice secret=42", "user:alice")
b = c.agent("bob",   "Help Bob.");   b.run("Bob   secret=99", "user:bob")
pid_b = next(x["pid"] for x in c.list_agents() if x["name"]=="bob")
print(f"[4] alice_ns={c.namespace_packet_count('ns:alice')}  bob_ns={c.namespace_packet_count('ns:bob')}")
print(f"    bob reads alice cid → {c.try_read(pid_b, cid1)[:30]}")

# 5. Audit trail ──────────────────────────────────────────────────────────────
print("[5] last 3 audit ops:")
for e in c.audit_tail(3):
    print(f"    [{e['outcome']:8s}] {e['operation']:20s}  {e['duration_us']}µs")

print("\nkernel_stats:", c.kernel_stats())
