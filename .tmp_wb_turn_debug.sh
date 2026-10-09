#!/usr/bin/env bash
set -euo pipefail
WORKDIR=$(cat /tmp/wb-repro-latest)
cd "$WORKDIR"
PID=$(cat pid)
SID=$(cat sid)
BASE=https://try.cnktros.com
echo "WORKDIR=$WORKDIR PID=$PID SID=$SID"

# Show prior empty turn file sizes
ls -la turn*.json 2>/dev/null || true
echo "turn1 bytes=$(wc -c < turn1.json 2>/dev/null || echo 0)"

python3 -c "import json; open('turn_body.json','w').write(json.dumps({'message':'Who are you?','model':''}))"

echo "=== POST turn file body ==="
curl -sS -D turn_headers.txt -o turn_retry.json -w "http=%{http_code} time_total=%{time_total}\n" \
  --max-time 25 \
  -X POST \
  -H @auth.hdr \
  -H 'Content-Type: application/json' \
  --data-binary @turn_body.json \
  "$BASE/api/v1/agents/${PID}/workbench/sessions/${SID}/turn" || echo "curl_rc=$?"
echo "--- headers ---"
head -40 turn_headers.txt || true
echo "--- body ---"
python3 -c "import pathlib; p=pathlib.Path('turn_retry.json'); print(p.read_text()[:2500] if p.exists() else 'MISSING')"

echo "=== POST with x-api-key ==="
curl -sS -D turn_headers2.txt -o turn_retry2.json -w "http=%{http_code} time_total=%{time_total}\n" \
  --max-time 25 \
  -X POST \
  -H "x-api-key: $(cat api_key)" \
  -H 'Content-Type: application/json' \
  --data-binary @turn_body.json \
  "$BASE/api/v1/agents/${PID}/workbench/sessions/${SID}/turn" || echo "curl_rc=$?"
head -30 turn_headers2.txt || true
python3 -c "import pathlib; p=pathlib.Path('turn_retry2.json'); print(p.read_text()[:2500] if p.exists() else 'MISSING')"

echo "=== POST plain -d ==="
curl -sS -D turn_headers3.txt -o turn_retry3.json -w "http=%{http_code} time_total=%{time_total}\n" \
  --max-time 25 \
  -H @auth.hdr -H 'Content-Type: application/json' \
  -d '{"message":"Who are you?"}' \
  "$BASE/api/v1/agents/${PID}/workbench/sessions/${SID}/turn" || echo "curl_rc=$?"
head -30 turn_headers3.txt || true
python3 -c "import pathlib; p=pathlib.Path('turn_retry3.json'); print(p.read_text()[:2500] if p.exists() else 'MISSING')"

# Check if route exists via OpenAPI / agents routes
echo "=== probe workbench posture ==="
curl -sS -o posture.json -w "http=%{http_code} time=%{time_total}\n" -H @auth.hdr "$BASE/api/v1/workbench/posture" || true
python3 -c "import pathlib; print(pathlib.Path('posture.json').read_text()[:800] if pathlib.Path('posture.json').exists() else 'no')"

echo "=== list routes snippet from /api/v1 ==="
curl -sS -o apiroot.json -w "http=%{http_code}\n" -H @auth.hdr "$BASE/api/v1" || true
python3 - <<'PY'
import json
try:
  d=json.load(open('apiroot.json'))
except Exception as e:
  print('fail',e); raise SystemExit
s=json.dumps(d)
for needle in ['workbench','/turn','playground']:
  print(needle, s.lower().count(needle.lower()))
# print paths containing workbench
def walk(o,path=''):
  if isinstance(o, dict):
    for k,v in o.items():
      if 'workbench' in str(k).lower() or 'workbench' in str(v).lower()[:200]:
        print('hit', path+'/'+str(k), str(v)[:120])
      walk(v, path+'/'+str(k))
  elif isinstance(o, list):
    for i,v in enumerate(o[:50]):
      walk(v, path+f'[{i}]')
walk(d)
PY
