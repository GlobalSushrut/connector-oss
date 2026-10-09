#!/bin/bash
# DevGuard Windsurf hook — called BEFORE every file write and command.
# Windsurf protocol: exit 2 to BLOCK, exit 0 to allow.
# DO NOT REMOVE — installed by `devguard connect windsurf`.

DG="/tmp/cursor-sandbox-cache/5abf50820e2eb3cac5a00bc226ef8d1c/cargo-target/debug/deps/devguard-b0b35022f3698903"
CONFIG="devguard.yaml"

# Managed repositories fail closed if the handler or policy is unavailable.
if [ ! -x "$DG" ] || [ ! -f "$CONFIG" ]; then
    echo "[DevGuard] DENY: handler or policy is unavailable" >&2
    exit 2
fi

PAYLOAD="$(cat)"
export DEVGUARD_HOOK_PAYLOAD="$PAYLOAD"
if ! command -v python3 >/dev/null 2>&1; then
    echo "[DevGuard] DENY: python3 is required to parse Windsurf hook input" >&2
    exit 2
fi
EVENT="${WINDSURF_HOOK_EVENT:-}"
FILE="${WINDSURF_FILE_PATH:-}"
COMMAND="${WINDSURF_COMMAND:-}"
if [ -z "$EVENT" ]; then
    EVENT="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{}"); print(d.get("agent_action_name") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$FILE" ]; then
    FILE="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{}"); i=d.get("tool_info") or {}; print(i.get("file_path") or i.get("path") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$COMMAND" ]; then
    COMMAND="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{}"); i=d.get("tool_info") or {}; print(i.get("command_line") or i.get("command") or "")' 2>/dev/null)" || exit 2
fi

case "$EVENT" in
    pre_read_code)
        if [ -n "$FILE" ] && ! result=$("$DG" check file read "$FILE" --config "$CONFIG" 2>&1); then
            echo "[DevGuard] READ BLOCKED: $FILE"
            echo "  $result"
            exit 2
        fi
        ;;

    pre_write_code)
        if [ -n "$FILE" ]; then
            if ! result=$("$DG" check file write "$FILE" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] WRITE BLOCKED: $FILE"
                echo "  Reason: $result"
                echo "  Role does not allow writing to this path."
                exit 2
            fi
        fi
        ;;

    pre_run_command)
        if [ -n "$COMMAND" ]; then
            if ! result=$("$DG" check exec "$COMMAND" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] COMMAND BLOCKED: $COMMAND"
                echo "  Reason: $result"
                echo "  Role does not allow running this command."
                exit 2
            fi
        fi
        ;;
esac

exit 0
