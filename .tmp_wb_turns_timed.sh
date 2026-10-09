#!/usr/bin/env bash
set -euo pipefail
BASE=https://try.cnktros.com
EMAIL="repro-stuck-$(date +%s)@example.com"
WORKDIR=/tmp/wb-repro-$$
mkdir -p "$WORKDIR"
cd "$WORKDIR"
echo "$WORKDIR" > /tmp/wb-repro-latest
echo "EMAIL=$EMAIL WORKDIR=$WORKDIR"

curl -sS -o health.json -w "health http=%{http_code} time=%{time_total}\n" "$BASE/health"
python3 -c "import json;d=json.load(open('health.json'));print('agents',d.get('agents'),'status',d.get('status'))"

curl -sS -o session.json -w "session http=%{http_code} time=%{time_total}\n" \
  -X POST "$BASE/api/v1/playground/session" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"label\":\"workbench-stuck-repro2\"}"
python3 <<'PY'
import json
d=json.load(open('session.json'))
print('ok',d.get('ok'),'demo',d.get('demo_agent_pid'))
open('api_key','w').write(d.get('api_key') or '')
pid=d.get('demo_agent_pid') or ''
if not pid and d.get('agents'):
  pid=(d['agents'][0] or {}).get('pid') or ''
open('pid','w').write(pid)
print('has_key',bool(d.get('api_key')),'pid',pid)
if not d.get('ok'):
  print('session_err', {k:d.get(k) for k in ('error','code','queued','hint')})
PY
test -s api_key && test -s pid

python3 -c 'import json; open("token_body.json","w").write(json.dumps({"api_key":open("api_key").read()}))'
curl -sS -o token.json -w "token http=%{http_code} time=%{time_total}\n" \
  -X POST "$BASE/api/v1/auth/token" -H 'Content-Type: application/json' --data-binary @token_body.json
python3 -c 'import json;d=json.load(open("token.json"));open("access_token","w").write(d.get("access_token") or "");print("has_access",bool(d.get("access_token")))'
test -s access_token
printf 'Authorization: Bearer %s\n' "$(cat access_token)" > auth.hdr
PID=$(cat pid)

curl -sS -o wb_create.json -w "wb_create http=%{http_code} time=%{time_total}\n" \
  -X POST -H @auth.hdr -H 'Content-Type: application/json' \
  -d '{"title":"Workbench","goal":"Consult and admit orders"}' \
  "$BASE/api/v1/agents/$PID/workbench/sessions"
python3 <<'PY'
import json
d=json.load(open('wb_create.json'))
sid=(d.get('session') or {}).get('session_id') or ''
open('sid','w').write(sid)
print('sid',sid,'phase',(d.get('session') or {}).get('phase'))
PY
SID=$(cat sid)
test -n "$SID"

analyze() {
  python3 - "$1" "$2" "$3" <<'PY'
import json,sys
label,path,rc=sys.argv[1],sys.argv[2],int(sys.argv[3])
raw=open(path,'rb').read() if __import__('os').path.exists(path) else b''
try:
  d=json.loads(raw.decode() or '{}')
except Exception as e:
  print(f'RESULT label={label!r} parse_fail rc={rc} bytes={len(raw)} err={e}')
  sys.exit(0)
s=d.get('session') or {}
events=d.get('events') or []
content=None
mutations=None
for ev in reversed(events):
  if isinstance(ev,dict) and ev.get('kind')=='assistant' and str(ev.get('content') or '').strip():
    content=str(ev['content'])[:180]
    mutations=(ev.get('payload') or {}).get('mutations')
    break
phase=s.get('phase')
ok=d.get('ok')
err=d.get('error') or d.get('code')
print(f'RESULT label={label!r} ok={ok} error={err} has_assistant_content={bool(content)} phase={phase} curl_rc={rc} mutations={mutations}')
if content:
  print('assistant_preview',repr(content))
PY
}

i=1
while IFS= read -r msg; do
  echo "=== TURN $i: $msg ==="
  python3 -c "import json,sys; open('body.json','w').write(json.dumps({'message':sys.argv[1],'model':''}))" "$msg"
  set +e
  curl -sS -o "turn${i}.json" -w "http=%{http_code} time_total=%{time_total} time_starttransfer=%{time_starttransfer}\n" \
    --max-time 16 \
    -X POST -H @auth.hdr -H 'Content-Type: application/json' \
    --data-binary @body.json \
    "$BASE/api/v1/agents/$PID/workbench/sessions/$SID/turn"
  rc=$?
  set -e
  analyze "$msg" "turn${i}.json" "$rc"
  if [ "$rc" -eq 28 ]; then
    echo "HUNG>15s on turn $i"
    echo "hung_turn=$i msg=$msg" >> hung.flag
  fi
  i=$((i+1))
done <<'MSGS'
Who are you?
What must you refuse?
hello briefly
MSGS

echo "DONE pid=$PID sid=$SID"
if [ -f hung.flag ]; then echo "HUNG_FLAGS:"; cat hung.flag; fi
