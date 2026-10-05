"""
Generate a demo .cast (asciinema v2) file then convert to GIF.
Uses real output from running 01_hello_world.py with DeepSeek.
Total runtime: ~28 seconds.
"""
import json, time, os, subprocess

WIDTH  = 100
HEIGHT = 28

PROMPT = "\r\n\033[1;32m❯\033[0m "
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[1;36m"
YELLOW = "\033[1;33m"
GREEN  = "\033[1;32m"
RED    = "\033[1;31m"


def write_cast(events, out_path):
    header = {
        "version": 2, "width": WIDTH, "height": HEIGHT,
        "timestamp": int(time.time()),
        "title": "connector-oss — Hello World Demo",
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
    }
    with open(out_path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for ts, text in events:
            f.write(json.dumps([round(ts, 4), "o", text]) + "\n")
    print(f"  wrote {out_path}")


def typewrite(events, t, text, cps=22):
    events.append((t, PROMPT))
    t += 0.05
    for ch in text:
        events.append((t, ch))
        t += 1.0 / cps + (0.04 if ch == " " else 0)
    return t


def emit(events, t, lines, gap=0.18):
    for line in lines:
        events.append((t, line + "\r\n"))
        t += gap
    return t


def build_events():
    events = []
    t = 0.0

    # Clear + banner
    events.append((t, "\033[2J\033[H"))
    t += 0.1
    t = emit(events, t, [
        f"{CYAN}╔══════════════════════════════════════════════════════════════════════════════════════╗{RESET}",
        f"{CYAN}║{RESET}  {BOLD}connector-oss{RESET}  ·  Rust memory kernel · HIPAA/SOC2 · CID provenance · DeepSeek  {CYAN}║{RESET}",
        f"{CYAN}╚══════════════════════════════════════════════════════════════════════════════════════╝{RESET}",
        "",
    ], gap=0.12)

    # pip install
    t = typewrite(events, t, "pip install connector-oss")
    t += 0.5
    events.append((t, "\r\n")); t += 0.2
    t = emit(events, t, [
        f"{DIM}Collecting connector-oss{RESET}",
        f"{DIM}  Downloading connector_oss-0.1.0-cp311-cp311-linux_x86_64.whl (2.1 MB){RESET}",
        f"{DIM}     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.1/2.1 MB  4.2 MB/s{RESET}",
        f"{DIM}Collecting vac-ffi>=0.1.0{RESET}",
        f"{DIM}  Downloading vac_ffi-0.1.0-cp311-cp311-linux_x86_64.whl (1.8 MB){RESET}",
        f"{DIM}     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.8/1.8 MB  5.1 MB/s{RESET}",
        f"{GREEN}Successfully installed connector-oss-0.1.0 vac-ffi-0.1.0{RESET}",
        "",
    ], gap=0.22)
    t += 0.3

    # export key
    t = typewrite(events, t, "export DEEPSEEK_API_KEY=sk-••••••••••••••••••••••••")
    t += 0.5
    events.append((t, "\r\n")); t += 0.4

    # run demo
    t = typewrite(events, t, "python demos/python/01_hello_world.py")
    t += 0.6
    events.append((t, "\r\n")); t += 0.3

    # connector repr
    events.append((t, f"{DIM}Connector(llm='deepseek:deepseek-chat', packets=0, agents=0, audit=0){RESET}\r\n"))
    t += 0.5

    # spinner while LLM responds
    for frame in ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠋", "⠙", "⠹", "⠸"]:
        events.append((t, f"\r  {YELLOW}{frame}{RESET} calling DeepSeek..."))
        t += 0.13
    events.append((t, "\r\033[K")); t += 0.05

    # real output (verbatim from actual run)
    t = emit(events, t, [
        f"{BOLD}[1]{RESET} text={CYAN}'2+2 equals 4.'{RESET}  trust={GREEN}80/100{RESET}  grade={GREEN}B{RESET}  ok={GREEN}True{RESET}",
        "",
        f"{BOLD}[2]{RESET} packets: {YELLOW}2{RESET} → {YELLOW}6{RESET}  audit_entries={YELLOW}8{RESET}",
        "",
        f"{BOLD}[3]{RESET} same_content_same_cid={GREEN}True{RESET}  diff_content_diff_cid={GREEN}True{RESET}",
        f"    cid={DIM}bafyreiacrdiuk3u23iqp5rlgxwk4lzaaslatobhatni5p2b6y7bsyg6xsq{RESET}",
        "",
        f"{BOLD}[4]{RESET} alice_ns={YELLOW}2{RESET}  bob_ns={YELLOW}2{RESET}",
        f"    bob reads alice cid → {RED}DENIED{RESET}{DIM}:Agent pid:000004 lacks read access to ns:alice{RESET}",
        "",
        f"{BOLD}[5]{RESET} last 3 audit ops:",
        f"    {GREEN}[Success ]{RESET} MemWrite              {DIM}187µs{RESET}",
        f"    {GREEN}[Success ]{RESET} MemWrite              {DIM}232µs{RESET}",
        f"    {RED}[Denied  ]{RESET} MemRead               {DIM} 74µs{RESET}",
        "",
        f"kernel_stats: agents={YELLOW}4{RESET}  namespaces={YELLOW}4{RESET}  packets={YELLOW}12{RESET}  audit_entries={YELLOW}22{RESET}",
    ], gap=0.19)

    # hold on final state
    events.append((t, PROMPT)); t += 2.8
    return events, t


if __name__ == "__main__":
    out_dir   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    os.makedirs(out_dir, exist_ok=True)
    cast_path = os.path.join(out_dir, "demo.cast")
    gif_path  = os.path.join(out_dir, "demo.gif")

    events, duration = build_events()
    write_cast(events, cast_path)
    print(f"  duration: {duration:.1f}s")

    agg = os.path.expanduser("~/.cargo/bin/agg")
    if not os.path.exists(agg):
        agg = "agg"
    try:
        subprocess.run([
            agg, cast_path, gif_path,
            "--font-size", "14",
            "--line-height", "1.4",
            "--cols", str(WIDTH),
            "--rows", str(HEIGHT),
            "--theme", "monokai",
            "--speed", "1.0",
        ], check=True)
        size_kb = os.path.getsize(gif_path) // 1024
        print(f"\n  GIF ready: {gif_path}  ({size_kb} KB)")
    except FileNotFoundError:
        print(f"\n  agg not found — cast ready at:\n  {cast_path}")
        print("  Install: cargo install --git https://github.com/asciinema/agg")
        print(f"  Then:    agg {cast_path} {gif_path} --theme monokai")
