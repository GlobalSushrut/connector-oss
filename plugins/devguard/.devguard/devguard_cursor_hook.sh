#!/bin/bash
# DevGuard Cursor hook — preToolUse hook called BEFORE every tool invocation.
# Cursor protocol: stdin JSON; exit 2 blocks the tool call.
# DO NOT REMOVE — installed by `devguard connect cursor`.

DG="/tmp/cursor-sandbox-cache/5abf50820e2eb3cac5a00bc226ef8d1c/cargo-target/debug/deps/devguard-b0b35022f3698903"
CONFIG="devguard.yaml"

if [ ! -x "$DG" ] || [ ! -f "$CONFIG" ]; then
    echo "[DevGuard] DENY: handler or policy is unavailable" >&2
    exit 2
fi

PAYLOAD="$(cat)"
export DEVGUARD_HOOK_PAYLOAD="$PAYLOAD"
if ! command -v python3 >/dev/null 2>&1; then
    echo "[DevGuard] DENY: python3 is required to parse Cursor hook input" >&2
    exit 2
fi
TOOL="${CURSOR_TOOL_NAME:-${hookEventName:-}}"
FILE="${CURSOR_FILE_PATH:-}"
CMD="${CURSOR_COMMAND:-}"
if [ -z "$TOOL" ]; then
    TOOL="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{}"); print(d.get("tool_name") or d.get("tool") or d.get("hook_event_name") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$FILE" ]; then
    FILE="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{}"); i=d.get("tool_input") or d.get("input") or {}; print(i.get("file_path") or i.get("path") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$CMD" ]; then
    CMD="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{}"); i=d.get("tool_input") or d.get("input") or {}; print(i.get("command") or "")' 2>/dev/null)" || exit 2
fi

case "$TOOL" in
    editFile|writeFile|createFile|file_write|edit_file|Write|Edit)
        TARGET="$FILE"
        if [ -n "$TARGET" ]; then
            if ! result=$("$DG" check file write "$TARGET" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] CURSOR WRITE BLOCKED: $TARGET"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    readFile|file_read|Read)
        TARGET="$FILE"
        if [ -n "$TARGET" ]; then
            if ! result=$("$DG" check file read "$TARGET" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] CURSOR READ BLOCKED: $TARGET"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    runTerminalCommand|executeCommand|bash|Shell|Bash)
        COMMAND="$CMD"
        if [ -n "$COMMAND" ]; then
            if ! result=$("$DG" check exec "$COMMAND" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] CURSOR EXEC BLOCKED: $COMMAND"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
esac

exit 0
