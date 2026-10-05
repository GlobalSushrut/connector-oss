"""
Generate an architecture visualization .cast (asciinema v2) file then convert to GIF.
Visualizes the flow described in AGENT_INTERNALS.md.
Total runtime: ~60 seconds.
"""
import json, time, os, subprocess

WIDTH  = 120
HEIGHT = 40

PROMPT = "\r\n\033[1;32m❯\033[0m "
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[1;36m"
YELLOW = "\033[1;33m"
GREEN  = "\033[1;32m"
RED    = "\033[1;31m"
BLUE   = "\033[1;34m"
MAGENTA= "\033[1;35m"
WHITE  = "\033[1;37m"

def write_cast(events, out_path):
    header = {
        "version": 2, "width": WIDTH, "height": HEIGHT,
        "timestamp": int(time.time()),
        "title": "connector-oss — Agent Architecture",
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
    }
    with open(out_path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for ts, text in events:
            f.write(json.dumps([round(ts, 4), "o", text]) + "\n")
    print(f"  wrote {out_path}")

def clear(events, t):
    events.append((t, "\033[2J\033[H"))
    return t + 0.1

def typewrite(events, t, text, cps=30):
    for ch in text:
        events.append((t, ch))
        t += 1.0 / cps + (0.02 if ch == " " else 0)
    return t

def emit(events, t, lines, gap=0.05):
    for line in lines:
        events.append((t, line + "\r\n"))
        t += gap
    return t

def box(title, content, color=CYAN, width=80):
    border = "─" * (width - 2)
    lines = [
        f"{color}┌{border}┐{RESET}",
        f"{color}│{RESET} {BOLD}{title.center(width-4)}{RESET} {color}│{RESET}",
        f"{color}├{border}┤{RESET}",
    ]
    for line in content:
        lines.append(f"{color}│{RESET} {line.ljust(width-4)} {color}│{RESET}")
    lines.append(f"{color}└{border}┘{RESET}")
    return lines

def build_events():
    events = []
    t = 0.0

    # 1. Intro
    t = clear(events, t)
    t = emit(events, t, [
        "", "", "",
        f"{CYAN}   CONNECTOR-OSS ARCHITECTURE{RESET}".center(WIDTH),
        f"{DIM}   Visualizing the lifecycle of a single agent request{RESET}".center(WIDTH),
        "", "", "",
    ], gap=0.2)
    t += 1.0

    # 2. SDK Surface
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}1. SDK Surface{RESET}", ""])
    code = [
        f"c = Connector.from_config({GREEN}'hospital.yaml'{RESET})",
        f"agent = c.agent({GREEN}'triage'{RESET}, {GREEN}'You are an ER nurse...'{RESET})",
        f"",
        f"result = agent.run({GREEN}'Patient: chest pain, BP 158/95...'{RESET})",
    ]
    for line in code:
        t = typewrite(events, t, line)
        events.append((t, "\r\n"))
        t += 0.3
    t += 1.0

    # 3. DualDispatcher & Firewall
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}2. DualDispatcher & Firewall (Ring 3){RESET}", ""])
    
    t = emit(events, t, box("DualDispatcher", [
        f"Routing operation to kernels...",
        f"",
        f"{YELLOW}► Firewall Check{RESET}",
        f"{DIM}  Checking input against threat models...{RESET}",
    ], color=BLUE), gap=0.1)
    
    t += 0.5
    firewall_box = box("Firewall Verdict", [
        f"Injection Score: {GREEN}0.05{RESET} (Low)",
        f"Exfiltration:    {GREEN}0.00{RESET} (None)",
        f"Jailbreak:       {GREEN}0.02{RESET} (Low)",
        f"",
        f"Verdict: {GREEN}{BOLD}ALLOW{RESET}",
    ], color=RED, width=60)
    
    t = emit(events, t, [""] + firewall_box, gap=0.1)
    t += 1.5

    # 4. VAC Memory Kernel
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}3. VAC Memory Kernel (Ring 1){RESET}", ""])
    
    vac_lines = [
        f"{MAGENTA}SyscallRequest{RESET} {{",
        f"  agent_pid: {CYAN}'pid:000001'{RESET}",
        f"  operation: {YELLOW}MemWrite{RESET}",
        f"  payload:   {DIM}Patient: chest pain...{RESET}",
        f"}}",
    ]
    t = emit(events, t, vac_lines, gap=0.1)
    t += 0.5
    
    t = emit(events, t, ["", f"{DIM}Processing...{RESET}"], gap=0.1)
    t += 0.5
    
    t = emit(events, t, [
        f"  ► {BOLD}Content Addressing{RESET}: SHA3-256(DAG-CBOR) -> {YELLOW}bafyreihgvkebvhv...{RESET}",
        f"  ► {BOLD}Namespace Check{RESET}:    Write access to {CYAN}ns:triage{RESET} -> {GREEN}OK{RESET}",
        f"  ► {BOLD}Audit Log{RESET}:        Entry #17 HMAC-linked -> {GREEN}SECURE{RESET}",
    ], gap=0.3)
    t += 1.5

    # 5. AAPI Action Engine
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}4. AAPI Action Engine (Ring 2){RESET}", ""])
    
    aapi_lines = [
        f"{BLUE}Policy Check{RESET}:",
        f"  Action:   {YELLOW}llm:deepseek:chat{RESET}",
        f"  Role:     {CYAN}triage_nurse{RESET}",
        f"  Resource: {DIM}any{RESET}",
    ]
    t = emit(events, t, aapi_lines, gap=0.1)
    t += 0.5
    
    t = emit(events, t, [
        f"",
        f"  ► {BOLD}PolicyRule{RESET}: {GREEN}ALLOW{RESET} (priority 100)",
        f"  ► {BOLD}Budget{RESET}:     Remaining 9850/10000 tokens",
        f"  ► {BOLD}Vakya{RESET}:      Issued capability token {YELLOW}vk_8f7a2d...{RESET}",
    ], gap=0.3)
    t += 1.5

    # 6. LLM & Cognitive Loop (Detailed)
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}5. BindingEngine: The Cognitive Loop{RESET}", ""])

    # Phase 1: Perceive
    t = emit(events, t, box("Phase 1: PERCEIVE", [
        f"Input: {CYAN}'Patient: chest pain...'{RESET}",
        f"  ► Entities: {YELLOW}[chest pain, BP 158/95, hypertension]{RESET}",
        f"  ► Claims:   {YELLOW}3 claims extracted{RESET}",
        f"  ► Quality:  {GREEN}85/100{RESET}",
    ], color=MAGENTA), gap=0.1)
    t += 2.0

    # Phase 2: Retrieve
    t = emit(events, t, box("Phase 2: RETRIEVE", [
        f"Querying KnowledgeEngine...",
        f"  ► RAG:      {YELLOW}Protocol_ChestPain_v4.pdf{RESET}",
        f"  ► Graph:    {YELLOW}John_Doe -> has_condition -> Hypertension{RESET}",
        f"  ► Memory:   {YELLOW}Previous visit (CID bafyre...){RESET}",
    ], color=BLUE), gap=0.1)
    t += 2.0

    # Phase 3: Reason
    t = emit(events, t, box("Phase 3: REASON", [
        f"Planning steps...",
        f"  1. Assess urgency (TIMI score)",
        f"  2. Check drug interactions",
        f"  3. Generate triage response",
    ], color=YELLOW), gap=0.1)
    t += 2.0

    # Spinner for LLM
    events.append((t, f"\n     {YELLOW}⠋{RESET} Calling DeepSeek LLM..."))
    for frame in ["⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] * 3:
        t += 0.1
        events.append((t, f"\r     {YELLOW}{frame}{RESET} Calling DeepSeek LLM..."))
    t += 0.2
    events.append((t, f"\r     {GREEN}✓{RESET} Response received (1.2s)\r\n"))
    t += 1.0

    # Phase 4 & 5
    t = emit(events, t, [
        f"",
        f"  ► {CYAN}Reflect{RESET}: Confidence 0.9, no contradictions",
        f"  ► {CYAN}Act{RESET}:     Commit decision to VAC Kernel -> CID {YELLOW}bafyreigima...{RESET}",
    ], gap=0.3)
    t += 2.5

    # 7. Trust Computer
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}6. Trust Computer (5 Dimensions){RESET}", ""])
    
    dims = [
        ("Memory Integrity",    "20/20", "Hash match"),
        ("Audit Completeness",  "20/20", "No gaps"),
        ("Authz Coverage",      "20/20", "Vakya present"),
        ("Decision Provenance", "20/20", "Evidence linked"),
        ("Operational Health",  "20/20", "Lifecycle OK"),
    ]
    
    t = emit(events, t, [f"Computing verifiable trust score from kernel state..."], gap=0.5)
    t += 0.5
    
    for name, score, note in dims:
        bar = "█" * 20
        t = emit(events, t, [f"  {name:20} {GREEN}{bar}{RESET} {score} ({note})"], gap=0.1)
    
    t += 0.5
    t = emit(events, t, [
        "",
        f"  {BOLD}Total Trust Score:{RESET} {GREEN}100/100{RESET} (Grade A+)",
    ], gap=0.1)
    t += 1.5

    # 8. Final Output
    t = clear(events, t)
    t = emit(events, t, [f"{BOLD}7. Final Result{RESET}", ""])
    
    output_obj = [
        f"PipelineOutput {{",
        f"  text:        {DIM}\"Urgency 1. Differentials: ACS...\"{RESET}",
        f"  trust:       {GREEN}100{RESET}",
        f"  trust_grade: {GREEN}\"A+\"{RESET}",
        f"  cid:         {YELLOW}\"bafyreigima...\"{RESET}",
        f"  trace_id:    {CYAN}\"pipe:triage\"{RESET}",
        f"  provenance:  {{ kernel_verified: 2, total: 2 }}",
        f"}}",
    ]
    t = emit(events, t, output_obj, gap=0.1)
    t += 2.0
    
    return events, t

if __name__ == "__main__":
    out_dir   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    os.makedirs(out_dir, exist_ok=True)
    cast_path = os.path.join(out_dir, "arch.cast")
    gif_path  = os.path.join(out_dir, "arch.gif")

    events, duration = build_events()
    write_cast(events, cast_path)
    print(f"  duration: {duration:.1f}s")

    agg = os.path.expanduser("~/.cargo/bin/agg")
    if not os.path.exists(agg):
        agg = "agg"
    
    print("Converting to GIF...")
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
    except Exception as e:
        print(f"Error running agg: {e}")
        print(f"Cast file available at: {cast_path}")
