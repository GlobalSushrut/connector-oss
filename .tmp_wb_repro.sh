#!/usr/bin/env bash
set -euo pipefail
BASE=https://try.cnktros.com
EMAIL="repro-stuck-$(date +%s)@example.com"
WORKDIR=/tmp/wb-repro-$$
mkdir -p "$WORKDIR"
cd "$WORKDIR"
echo "EMAIL=$EMAIL" | tee /tmp/wb-repro-latest-meta
echo "$WORKDIR" > /tmp/wb-repro-latest

echo "=== 1) HEALTH ==="
curl -sS -o health.json -w "http=%{http_code} time=%{time_total}\n" "$BASE/health"
python3 -c "import json;d=json.load(open('health.json'));print('status',d.get('status'),'agents',d.get('agents'),'mode',d.get('mode'))"

echo "=== 2) START SESSION ==="
curl -sS -o session.json -w "http=%{http_code} time=%{time_total}\n" \
  -X POST "$BASE/api/v1/playground/session" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"label\":\"workbench-stuck-repro\"}"

python3 <<'PY'
import json
d=json.load(open('session.json'))
for k in ('ok','session_id','tenant_id','agent_pids','queued','error','code','hint','agents_created'):
    if k in d: print(f'{k}={d[k]!r}'[:500])
if isinstance(d.get('agents'), list):
    for a in d['agents']:
        if isinstance(a, dict):
            print('agent_pid', a.get('pid'), 'name', a.get('name') or a.get('label') or a.get('display_name'))
open('api_key','w').write(d.get('api_key') or '')
open('session_id','w').write(d.get('session_id') or '')
pids=list(d.get('agent_pids') or [])
if not pids and isinstance(d.get('agents'), list):
    pids=[a.get('pid') for a in d['agents'] if isinstance(a,dict) and a.get('pid')]
open('pid','w').write(pids[0] if pids else '')
print('has_api_key', bool(d.get('api_key')))
print('demo_pid', open('pid').read())
print('response_keys', sorted(d.keys()))
PY

test -s api_key && test -s pid || { echo FATAL_SESSION; python3 -c "import json;print(json.dumps({k:v for k,v in json.load(open('session.json')).items() if k!='api_key'},indent=2)[:3000])"; exit 1; }
PID=$(cat pid)

echo "=== 3) AUTH TOKEN EXCHANGE ==="
python3 -c 'import json; open("token_body.json","w").write(json.dumps({"api_key":open("api_key").read()}))'
curl -sS -o token.json -w "http=%{http_code} time=%{time_total}\n" \
  -X POST "$BASE/api/v1/auth/token" \
  -H 'Content-Type: application/json' \
  --data-binary @token_body.json
python3 <<'PY'
import json
d=json.load(open('token.json'))
at=d.get('access_token') or ''
open('access_token','w').write(at)
print('has_access', bool(at), 'tenant', d.get('tenant_id'), 'error', d.get('error'), 'code', d.get('code'))
PY
test -s access_token || { echo FATAL_TOKEN; exit 1; }
printf 'Authorization: Bearer %s\n' "$(cat access_token)" > auth.hdr
echo "=== 4) pid=$PID ==="

echo "=== 5) ENSURE WORKBENCH SESSION ==="
curl -sS -o wb_list.json -w "list http=%{http_code} time=%{time_total}\n" -H @auth.hdr "$BASE/api/v1/agents/$PID/workbench/sessions"
python3 <<'PY'
import json
d=json.load(open('wb_list.json'))
sessions=d.get('sessions') or []
print('list_ok', d.get('ok'), 'count', d.get('count'), 'n', len(sessions), 'err', d.get('error') or d.get('code'))
sid=sessions[0].get('session_id') if sessions else ''
open('sid','w').write(sid or '')
print('reuse_sid', bool(sid))
PY
SID=$(cat sid)
if [ -z "$SID" ]; then
  curl -sS -o wb_create.json -w "create http=%{http_code} time=%{time_total}\n" \
    -X POST -H @auth.hdr -H 'Content-Type: application/json' \
    -d '{"title":"Workbench","goal":"Consult and admit orders"}' \
    "$BASE/api/v1/agents/$PID/workbench/sessions"
  python3 <<'PY'
import json
d=json.load(open('wb_create.json'))
sid=(d.get('session') or {}).get('session_id') or d.get('session_id') or ''
open('sid','w').write(sid)
print('create_ok', d.get('ok'), 'sid_present', bool(sid), 'err', d.get('error') or d.get('code'))
s=d.get('session') or d
print('phase', s.get('phase') or s.get('status'))
if isinstance(s, dict): print('session_keys', sorted(s.keys())[:40])
PY
  SID=$(cat sid)
fi
test -n "$SID" || { echo FATAL_SID; exit 1; }
curl -sS -o wb_get.json -w "get http=%{http_code} time=%{time_total}\n" -H @auth.hdr "$BASE/api/v1/agents/$PID/workbench/sessions/$SID"
python3 -c "import json;d=json.load(open('wb_get.json'));s=d.get('session') or d;print('get_ok',d.get('ok'),'phase',s.get('phase') or s.get('status'),'err',d.get('error'))"

analyze_turn() {
  python3 - "$1" "$2" <<'PY'
import json,sys
path,rc=sys.argv[1],int(sys.argv[2])
try:
  raw=open(path,'rb').read()
  d=json.loads(raw.decode() or '{}')
except Exception as e:
  print(f'parse_fail rc={rc} err={e} bytes={len(open(path,"rb").read())}')
  sys.exit(0)
s=d.get('session') or d
content=None
msgs=s.get('messages') or s.get('journal') or s.get('entries') or d.get('messages') or []
if isinstance(msgs, list):
  for m in reversed(msgs):
    if not isinstance(m, dict):
      continue
    role=str(m.get('role') or m.get('kind') or m.get('speaker') or m.get('type') or '')
    text=m.get('content') or m.get('text') or m.get('body') or ''
    if role.lower() in ('assistant','agent') and str(text).strip():
      content=str(text)[:160]
      break
for key in ('assistant','last_assistant','reply','content','assistant_text'):
  v=s.get(key) if isinstance(s,dict) else None
  if isinstance(v, str) and v.strip():
    content=v[:160]; break
phase=s.get('phase') or s.get('status') or d.get('phase')
ok=d.get('ok')
err=d.get('error') or d.get('code') or (None if ok else 'not_ok')
print(f'ok={ok} error={err} has_assistant_content={bool(content)} phase={phase} curl_rc={rc}')
if content:
  print('assistant_preview=', repr(content[:160]))
if isinstance(s, dict):
  print('session_top_keys', sorted(s.keys())[:50])
  for k in ('consulting','last_error','turn_count'):
    if k in s: print(k, s.get(k))
  if isinstance(msgs, list):
    print('msg_count', len(msgs))
    if msgs and isinstance(msgs[-1], dict):
      last=msgs[-1]
      print('last_msg_keys', sorted(last.keys())[:30])
      print('last_role', last.get('role') or last.get('kind') or last.get('speaker') or last.get('type'))
PY
}

echo "=== 6/7) TIMED TURNS ==="
i=1
while IFS= read -r msg; do
  echo "--- TURN: $msg ---"
  out="turn${i}.json"
  set +e
  curl -sS -o "$out" -w "http=%{http_code} time_total=%{time_total} time_starttransfer=%{time_starttransfer}\n" \
    --max-time 20 \
    -X POST -H @auth.hdr -H 'Content-Type: application/json' \
    --data-binary @<(python3 -c "import json,sys; print(json.dumps({'message':sys.argv[1],'model':''}))" "$msg") \
    "$BASE/api/v1/agents/$PID/workbench/sessions/$SID"
  rc=$?
  set -e
  analyze_turn "$out" "$rc"
  i=$((i+1))
done <<'MSGS'
Who are you?
What must you refuse?
hello briefly
MSGS

echo "DONE WORKDIR=$WORKDIR PID=$PID"
