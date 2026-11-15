#!/usr/bin/env bash
# 전체 실행: 구성 → 패킷 캡처 → 연결 매트릭스 → 검사 → 정리.
# 검사가 하나라도 어긋나면 0이 아닌 값으로 끝난다(CI 실패).
# 결과는 out/ 에 남는다. root 권한이 필요하다(sudo ./run.sh).
set -euo pipefail
cd "$(dirname "$0")"
OUT=out; rm -rf "$OUT"; mkdir -p "$OUT"
FAIL=0

lab/teardown.sh
trap lab/teardown.sh EXIT
lab/setup.sh

req() { # req <출발 주소> <url> → 성공하면 0
  ip netns exec client curl -s -o /dev/null --max-time 2 --interface "$1" "$2"
}
check() { # check <설명> <기대값> <명령...>
  local name=$1 want=$2; shift 2
  if "$@"; then got=ALLOW; else got=DENY; fi
  if [ "$got" = "$want" ]; then mark=ok; else mark=MISMATCH; FAIL=1; fi
  printf '| %s | %s | %s | %s |\n' "$name" "$want" "$got" "$mark" | tee -a "$OUT/matrix.md"
}

# ── 1. 패킷 캡처: 같은 요청을 외부망(net 의 br0)과 터널 안쪽(gw-app)에서 동시에 본다 ──
ip netns exec net tcpdump -i br0   -n -l > "$OUT/capture_wan.txt"    2>/dev/null &
ip netns exec gw tcpdump -i gw-app -n -l > "$OUT/capture_inside.txt" 2>/dev/null &
sleep 1
req 10.9.0.2 http://10.0.2.10:8080/ || { echo "터널 경유 요청 실패"; FAIL=1; }
sleep 1
{ ip netns pids net; ip netns pids gw; } | xargs -r kill; sleep 0.5

ESP=$(grep -c 'ESP(spi=' "$OUT/capture_wan.txt" || true)
LEAK=$(grep -c -e '10\.9\.0\.2' -e '\.8080' "$OUT/capture_wan.txt" || true)
PLAIN=$(grep -c '10\.9\.0\.2\.[0-9]* > 10\.0\.2\.10\.8080' "$OUT/capture_inside.txt" || true)
[ "$ESP" -gt 0 ]   || { echo "FAIL: 외부망에 ESP 패킷이 없다"; FAIL=1; }
[ "$LEAK" -eq 0 ]  || { echo "FAIL: 외부망에 터널 안 주소·포트가 평문으로 보인다"; FAIL=1; }
[ "$PLAIN" -gt 0 ] || { echo "FAIL: 안쪽 구간에서 복호화된 요청이 보이지 않는다"; FAIL=1; }

# ── 2. 연결 매트릭스: 허용해야 할 쌍과 막아야 할 쌍을 모두 검사한다 ──
{ echo '| 경로 | 기대 | 결과 | 판정 |'; echo '|---|---|---|---|'; } | tee "$OUT/matrix.md"
check '터널 → app:8080'              ALLOW req 10.9.0.2 http://10.0.2.10:8080/
check '터널 → app:22 (허용 외 포트)' DENY  req 10.9.0.2 http://10.0.2.10:22/
check '터널 → db:5432 (허용 외 서버)' DENY  req 10.9.0.2 http://10.0.3.20:5432/
check '터널 없이 → app:8080'         DENY  req 10.0.1.2 http://10.0.2.10:8080/

# ── 3. 차단 기록: 차단이 이유별 카운터에 남았는지 ──
ip netns exec gw nft list counters > "$OUT/counters.txt"
count() { awk -v n="$1" '$1=="counter" && $2==n {f=1} f && $1=="packets" {print $2; exit}' "$OUT/counters.txt"; }
A=$(count allow_app); N=$(count deny_no_tunnel); D=$(count deny_not_allowed)
[ "${A:-0}" -gt 0 ] && [ "${N:-0}" -gt 0 ] && [ "${D:-0}" -gt 0 ] \
  || { echo "FAIL: 카운터가 비어 있다 (allow=$A no_tunnel=$N not_allowed=$D)"; FAIL=1; }

# SA 는 키를 지우고 남긴다
ip -n gw xfrm state | sed -E 's/0x[0-9a-f]{16,}/(key 생략)/' > "$OUT/xfrm_state.txt"
ip -n gw xfrm policy > "$OUT/xfrm_policy.txt"

# ── 요약 (GitHub Actions 요약 화면에 그대로 붙인다) ──
{
  echo '## 연결 매트릭스'; cat "$OUT/matrix.md"; echo
  echo '## 차단·허용 카운터 (게이트웨이 nftables)'
  echo '| 카운터 | 패킷 수 |'; echo '|---|---|'
  echo "| allow_app | $A |"; echo "| deny_no_tunnel | $N |"; echo "| deny_not_allowed | $D |"; echo
  echo "## 패킷 캡처: 외부망 (br0) — ESP $ESP개, 평문 노출 $LEAK개"
  echo '```'; head -8 "$OUT/capture_wan.txt"; echo '```'
  echo "## 패킷 캡처: 터널 안쪽 (gw-app) — 복호화된 요청 $PLAIN개"
  echo '```'; head -8 "$OUT/capture_inside.txt"; echo '```'
  echo '## IPsec SA (게이트웨이, 키 생략)'
  echo '```'; cat "$OUT/xfrm_state.txt"; echo '```'
} > "$OUT/summary.md"
cat "$OUT/summary.md"

[ "$FAIL" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"
