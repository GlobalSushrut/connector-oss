#!/usr/bin/env python3
"""Demo Handler - Unified management for all Connector demos (demo1-7)

Usage:
  python demos/demo_handler.py list                    # list all available demos
  python demos/demo_handler.py status                  # check status of all demos
  python demos/demo_handler.py run <demo>              # run specific demo
  python demos/demo_handler.py bootstrap <demo>        # bootstrap specific demo
  python demos/demo_handler.py preflight <demo>        # run preflight checks
  python demos/demo_handler.py bootstrap-all           # bootstrap all demos
  python demos/demo_handler.py run-all                 # run all demos in sequence
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add demos directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import CONNECTOR_DEV_MODE, CONNECTOR_API_KEY, CONNECTOR_URL

# =============================================================================
# DEMO CONFIGURATION
# =============================================================================

DEMOS = {
    "demo1": {
        "name": "Enterprise Demo",
        "description": "Investor-grade enterprise demo with clinical governance",
        "script": "demo.py",
        "directory": ".",
        "commands": ["bootstrap", "run_agent", "run_failure_case", "run_phi_case"],
        "main_command": "demo.py",
    },
    "demo2": {
        "name": "Coding Workflow Demo", 
        "description": "Governed coding workflow with CLS contracts",
        "script": "demo2/workflow_demo.py",
        "directory": "demo2",
        "commands": ["preflight", "bootstrap", "run"],
        "main_command": "demo2/workflow_demo.py",
    },
    "demo3": {
        "name": "Security Attack Demo",
        "description": "Security attack scenarios and defense demonstrations",
        "script": "demo3/attack_demo.py", 
        "directory": "demo3",
        "commands": ["preflight", "bootstrap", "run"],
        "main_command": "demo3/attack_demo.py",
    },
    "demo4": {
        "name": "Stability Demo",
        "description": "System stability and deterministic execution",
        "script": "demo4/stable_thinking.py",
        "directory": "demo4", 
        "commands": ["preflight", "bootstrap", "run"],
        "main_command": "demo4/stable_thinking.py",
    },
    "demo5": {
        "name": "Selective Context Demo",
        "description": "Identity-aware execution with selective context filtering",
        "script": "demo5/selective_context_demo.py",
        "directory": "demo5",
        "commands": ["preflight", "bootstrap", "run"],
        "main_command": "demo5/selective_context_demo.py",
    },
    "demo6": {
        "name": "Witness & Deterministic Demo", 
        "description": "Witness outbound API governance and deterministic execution",
        "script": "demo6/witnessctl_google_demo.py",
        "directory": "demo6",
        "commands": ["preflight", "bootstrap", "run"],
        "main_command": "demo6/witnessctl_google_demo.py",
    }
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_env_vars() -> Dict[str, str]:
    """Get required environment variables for demo execution."""
    return {
        "CONNECTOR_URL": CONNECTOR_URL,
        "CONNECTOR_DEV_MODE": CONNECTOR_DEV_MODE or "",
        "CONNECTOR_API_KEY": CONNECTOR_API_KEY or "",
    }

def check_auth() -> Dict[str, Any]:
    """Check if authentication is properly configured."""
    env_vars = get_env_vars()
    
    if env_vars["CONNECTOR_DEV_MODE"]:
        return {
            "ok": True,
            "mode": "dev",
            "message": "Using dev mode authentication"
        }
    
    if env_vars["CONNECTOR_API_KEY"]:
        return {
            "ok": True, 
            "mode": "api_key",
            "message": "Using API key authentication"
        }
    
    return {
        "ok": False,
        "mode": "none",
        "message": "No authentication configured - set CONNECTOR_API_KEY or CONNECTOR_DEV_MODE=1"
    }

def run_demo_command(demo_id: str, command: str, args: List[str] = None) -> int:
    """Run a specific demo command."""
    if demo_id not in DEMOS:
        print(f"Error: Unknown demo '{demo_id}'. Available demos: {list(DEMOS.keys())}")
        return 1
    
    demo = DEMOS[demo_id]
    script_path = Path(__file__).parent / demo["script"]
    
    if not script_path.exists():
        print(f"Error: Demo script not found: {script_path}")
        return 1
    
    # Prepare environment
    env = os.environ.copy()
    env.update(get_env_vars())
    
    # Build command
    cmd = ["python3", str(script_path), command]
    if args:
        cmd.extend(args)
    
    print(f"Running: {' '.join(cmd)}")
    print(f"Demo: {demo['name']} - {demo['description']}")
    print("-" * 60)
    
    try:
        # Change to demo directory if specified
        cwd = Path(__file__).parent
        if demo["directory"] != ".":
            cwd = cwd / demo["directory"]
        
        result = subprocess.run(cmd, cwd=cwd, env=env, check=False)
        return result.returncode
    except Exception as e:
        print(f"Error running demo: {e}")
        return 1

def check_demo_status(demo_id: str) -> Dict[str, Any]:
    """Check the status of a specific demo."""
    if demo_id not in DEMOS:
        return {"error": f"Unknown demo '{demo_id}'"}
    
    demo = DEMOS[demo_id]
    script_path = Path(__file__).parent / demo["script"]
    
    status = {
        "demo_id": demo_id,
        "name": demo["name"],
        "description": demo["description"],
        "script_exists": script_path.exists(),
        "script_path": str(script_path),
        "commands": demo["commands"],
    }
    
    # Check if demo can be imported (basic syntax check)
    if script_path.exists():
        try:
            # Try to get basic info by running with --help
            env = os.environ.copy()
            env.update(get_env_vars())
            result = subprocess.run(
                ["python3", str(script_path), "--help"],
                cwd=Path(__file__).parent / demo["directory"] if demo["directory"] != "." else Path(__file__).parent,
                env=env,
                capture_output=True,
                text=True,
                timeout=10
            )
            status["help_available"] = result.returncode == 0
            status["help_output"] = result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout
        except Exception as e:
            status["help_available"] = False
            status["error"] = str(e)
    
    return status

# =============================================================================
# COMMAND HANDLERS
# =============================================================================

def list_demos() -> int:
    """List all available demos."""
    auth = check_auth()
    print("Connector Demo Handler")
    print("=" * 50)
    print(f"Authentication: {auth['message']}")
    print()
    
    for demo_id, demo in DEMOS.items():
        status = check_demo_status(demo_id)
        status_icon = "✓" if status["script_exists"] else "✗"
        help_icon = "✓" if status.get("help_available", False) else "✗"
        
        print(f"{status_icon} {demo_id}: {demo['name']}")
        print(f"   {demo['description']}")
        print(f"   Script: {demo['script']}")
        print(f"   Commands: {', '.join(demo['commands'])}")
        print(f"   Help available: {help_icon}")
        print()
    
    return 0

def check_all_status() -> int:
    """Check status of all demos."""
    auth = check_auth()
    print("Connector Demo Status Check")
    print("=" * 50)
    print(f"Authentication: {auth['message']}")
    print()
    
    all_good = True
    for demo_id in DEMOS.keys():
        status = check_demo_status(demo_id)
        
        if "error" in status:
            print(f"✗ {demo_id}: {status['error']}")
            all_good = False
        else:
            script_ok = "✓" if status["script_exists"] else "✗"
            help_ok = "✓" if status.get("help_available", False) else "✗"
            print(f"{script_ok} {demo_id}: {status['name']}")
            print(f"   Script exists: {script_ok}")
            print(f"   Help available: {help_ok}")
            
            if not status["script_exists"] or not status.get("help_available", False):
                all_good = False
        print()
    
    if all_good:
        print("All demos are ready!")
        return 0
    else:
        print("Some demos have issues. See above for details.")
        return 1

def bootstrap_all() -> int:
    """Bootstrap all demos in sequence."""
    print("Bootstrapping all demos...")
    print("=" * 50)
    
    auth = check_auth()
    if not auth["ok"]:
        print(f"Authentication error: {auth['message']}")
        return 1
    
    failed_demos = []
    
    for demo_id in sorted(DEMOS.keys()):
        print(f"\nBootstrapping {demo_id}...")
        result = run_demo_command(demo_id, "bootstrap")
        if result != 0:
            failed_demos.append(demo_id)
            print(f"✗ {demo_id} bootstrap failed")
        else:
            print(f"✓ {demo_id} bootstrap successful")
    
    print("\n" + "=" * 50)
    if failed_demos:
        print(f"Bootstrap failed for: {', '.join(failed_demos)}")
        return 1
    else:
        print("All demos bootstrapped successfully!")
        return 0

def run_all() -> int:
    """Run all demos in sequence."""
    print("Running all demos...")
    print("=" * 50)
    
    auth = check_auth()
    if not auth["ok"]:
        print(f"Authentication error: {auth['message']}")
        return 1
    
    failed_demos = []
    
    for demo_id in sorted(DEMOS.keys()):
        print(f"\nRunning {demo_id}...")
        result = run_demo_command(demo_id, "run", ["--no-wait"])
        if result != 0:
            failed_demos.append(demo_id)
            print(f"✗ {demo_id} run failed")
        else:
            print(f"✓ {demo_id} run successful")
    
    print("\n" + "=" * 50)
    if failed_demos:
        print(f"Run failed for: {', '.join(failed_demos)}")
        return 1
    else:
        print("All demos ran successfully!")
        return 0

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Connector Demo Handler")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List command
    subparsers.add_parser("list", help="List all available demos")
    
    # Status command
    subparsers.add_parser("status", help="Check status of all demos")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run a specific demo")
    run_parser.add_argument("demo", choices=list(DEMOS.keys()), help="Demo to run")
    run_parser.add_argument("args", nargs="*", help="Additional arguments for demo")
    
    # Bootstrap command
    bootstrap_parser = subparsers.add_parser("bootstrap", help="Bootstrap a specific demo")
    bootstrap_parser.add_argument("demo", choices=list(DEMOS.keys()), help="Demo to bootstrap")
    
    # Preflight command
    preflight_parser = subparsers.add_parser("preflight", help="Run preflight checks for a specific demo")
    preflight_parser.add_argument("demo", choices=list(DEMOS.keys()), help="Demo to check")
    
    # Bootstrap all command
    subparsers.add_parser("bootstrap-all", help="Bootstrap all demos")
    
    # Run all command
    subparsers.add_parser("run-all", help="Run all demos")
    
    args = parser.parse_args()
    
    if args.command == "list":
        return list_demos()
    elif args.command == "status":
        return check_all_status()
    elif args.command == "run":
        return run_demo_command(args.demo, "run", args.args)
    elif args.command == "bootstrap":
        return run_demo_command(args.demo, "bootstrap")
    elif args.command == "preflight":
        return run_demo_command(args.demo, "preflight")
    elif args.command == "bootstrap-all":
        return bootstrap_all()
    elif args.command == "run-all":
        return run_all()
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
