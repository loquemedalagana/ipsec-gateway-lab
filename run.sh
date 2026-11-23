#!/usr/bin/env bash
# 전체 실행: 구성 → 패킷 캡처 → 연결 매트릭스 → 차단 기록(카운터·건별 로그) → 장애 실험 → 정리.
# 검사가 하나라도 어긋나면 0이 아닌 값으로 끝난다(CI 실패).
# 결과는 out/ 에 남는다. root 권한이 필요하다(sudo ./run.sh).
set -euo pipefail
cd "$(dirname "$0")"
OUT=out; rm -rf "$OUT"; mkdir -p "$OUT"
FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }

lab/teardown.sh
trap lab/teardown.sh EXIT
lab/setup.sh

# 요청 한 번을 보내고 결과를 한 단어로 돌려준다: outcome <출발 주소> <url>
#   ALLOW   = 응답을 받음
#   DROP    = 시간 초과(curl 28). 패킷이 조용히 버려졌다 → 정책이 막은 것
#   REFUSED = 연결 거부(curl 7). 서버까지 갔는데 포트가 닫혀 있다 → 정책이 막은 것이 아님
outcome() {
  local rc=0
  ip netns exec client curl -s -o /dev/null --max-time 2 --interface "$1" "$2" || rc=$?
  case $rc in 0) echo ALLOW;; 28) echo DROP;; 7) echo REFUSED;; *) echo "ERR($rc)";; esac
}
check() { # check <설명> <기대값> <출발 주소> <url>
  local got mark=ok; got=$(outcome "$3" "$4")
  [ "$got" = "$2" ] || { mark=MISMATCH; FAIL=1; }
  printf '| %s | %s | %s | %s |\n' "$1" "$2" "$got" "$mark" | tee -a "$OUT/matrix.md"
}

# 같은 요청을 외부망(net 의 br0)과 터널 안쪽(gw-app)에서 동시에 캡처한다
cap_start() { # cap_start <파일 이름 앞부분>
  ip netns exec net tcpdump -i br0    -n -l > "$OUT/$1_wan.txt"    2>/dev/null &
  ip netns exec gw  tcpdump -i gw-app -n -l > "$OUT/$1_inside.txt" 2>/dev/null &
  sleep 1
}
cap_stop() { sleep 1; { ip netns pids net; ip netns pids gw; } | xargs -r kill; sleep 0.5; }
n_esp()   { grep -c 'ESP(spi=' "$OUT/$1_wan.txt" || true; }                       # 외부망의 ESP 패킷 수
n_leak()  { grep -c -e '10\.9\.0\.2' -e '\.8080' "$OUT/$1_wan.txt" || true; }     # 외부망에 평문으로 보인 수
n_plain() { grep -c '> 10\.0\.2\.10\.8080' "$OUT/$1_inside.txt" || true; }        # app 에 도착한 요청 패킷 수
# 게이트웨이가 차단한 패킷의 건별 로그: nftables 가 nflog 그룹으로 보낸 것을 이유별 파일로 받는다
log_start() {
  ip netns exec gw tcpdump -i nflog:1 -n -l > "$OUT/drop_no_tunnel.txt"   2>/dev/null &
  ip netns exec gw tcpdump -i nflog:2 -n -l > "$OUT/drop_not_allowed.txt" 2>/dev/null &
  sleep 1
}
log_stop() { sleep 1; ip netns pids gw | xargs -r kill; sleep 0.5; }
n_log() { grep -c -E "$2" "$OUT/$1.txt" || true; }   # n_log <파일 이름> <정규식>: 맞는 로그 줄 수
xstat()   { ip netns exec "$1" cat /proc/net/xfrm_stat | awk '$2>0 {printf "%s=%s ", $1, $2} END {print ""}'; }

# ── 1. 패킷 캡처 ──
cap_start capture
[ "$(outcome 10.9.0.2 http://10.0.2.10:8080/)" = ALLOW ] || fail "터널 경유 요청 실패"
cap_stop
ESP=$(n_esp capture); LEAK=$(n_leak capture); PLAIN=$(n_plain capture)
[ "$ESP" -gt 0 ]   || fail "외부망에 ESP 패킷이 없다"
[ "$LEAK" -eq 0 ]  || fail "외부망에 터널 안 주소·포트가 평문으로 보인다"
[ "$PLAIN" -gt 0 ] || fail "안쪽 구간에서 복호화된 요청이 보이지 않는다"

# ── 2. 연결 매트릭스: 허용해야 할 쌍과 막아야 할 쌍을 모두 검사한다 ──
log_start
{ echo '| 경로 | 기대 | 결과 | 판정 |'; echo '|---|---|---|---|'; } | tee "$OUT/matrix.md"
check '터널 → app:8080'               ALLOW 10.9.0.2 http://10.0.2.10:8080/
check '터널 → app:22 (허용 외 포트)'  DROP  10.9.0.2 http://10.0.2.10:22/
check '터널 → db:5432 (허용 외 서버)' DROP  10.9.0.2 http://10.0.3.20:5432/
check '터널 없이 → app:8080'          DROP  10.0.1.2 http://10.0.2.10:8080/
log_stop

# ── 3. 차단 기록: 차단이 이유별 카운터에 남았는지 ──
ip netns exec gw nft list counters > "$OUT/counters.txt"
count() { awk -v n="$1" '$1=="counter" && $2==n {f=1} f && $1=="packets" {print $2; exit}' "$OUT/counters.txt"; }
A=$(count allow_app); N=$(count deny_no_tunnel); D=$(count deny_not_allowed)
[ "${A:-0}" -gt 0 ] && [ "${N:-0}" -gt 0 ] && [ "${D:-0}" -gt 0 ] \
  || fail "카운터가 비어 있다 (allow=$A no_tunnel=$N not_allowed=$D)"

# ── 3-1. 건별 로그: 차단된 패킷마다 "누가 어디로"가 남았는지 ──
# 차단한 것은 이유에 맞는 파일에 있어야 하고, 허용한 것은 어느 파일에도 없어야 한다.
L_N=$(n_log drop_no_tunnel '^[0-9]'); L_D=$(n_log drop_not_allowed '^[0-9]')
L_PORT=$(n_log drop_not_allowed '10\.9\.0\.2\.[0-9]+ > 10\.0\.2\.10\.22:')      # 허용 외 포트
L_DB=$(n_log drop_not_allowed '10\.9\.0\.2\.[0-9]+ > 10\.0\.3\.20\.5432:')     # 허용 외 서버
L_RAW=$(n_log drop_no_tunnel '10\.0\.1\.2\.[0-9]+ > 10\.0\.2\.10\.8080:')      # IPsec 미적용
L_ALLOWED=$(cat "$OUT"/drop_*.txt | grep -c -E '10\.9\.0\.2\.[0-9]+ > 10\.0\.2\.10\.8080:' || true)
[ "$L_PORT" -gt 0 ]    || fail "로그에 '터널 → app:22' 차단이 없다"
[ "$L_DB" -gt 0 ]      || fail "로그에 '터널 → db:5432' 차단이 없다"
[ "$L_RAW" -gt 0 ]     || fail "로그에 '터널 없이 → app:8080' 차단이 없다"
[ "$L_ALLOWED" -eq 0 ] || fail "허용한 요청(터널 → app:8080)이 차단 로그에 있다"
[ "$L_N" -eq "${N:-0}" ] && [ "$L_D" -eq "${D:-0}" ] \
  || fail "로그 줄 수가 카운터와 다르다 (no_tunnel 로그=$L_N 카운터=$N, not_allowed 로그=$L_D 카운터=$D)"

# SA 는 키를 지우고 남긴다
ip -n gw xfrm state | sed -E 's/0x[0-9a-f]{16,}/(key 생략)/' > "$OUT/xfrm_state.txt"
ip -n gw xfrm policy > "$OUT/xfrm_policy.txt"

# ── 4. 장애 실험: SA 가 사라지면 요청은 평문으로 새는가, 막히는가 ──
# 정책(SP)은 그대로 두고 SA 만 지운다. 기대: 요청은 실패하고, 평문은 어디에도 나가지 않는다.
# (a) 게이트웨이의 SA 만 삭제 — 클라이언트는 계속 암호화해 보내지만 게이트웨이가 풀 수 없다
ip -n gw xfrm state flush
cap_start fault_gw
F1=$(outcome 10.9.0.2 http://10.0.2.10:8080/)
cap_stop
F1_ESP=$(n_esp fault_gw); F1_LEAK=$(n_leak fault_gw); F1_IN=$(n_plain fault_gw); F1_STAT=$(xstat gw)
[ "$F1" != ALLOW ]    || fail "(a) SA 가 없는데 요청이 성공했다"
[ "$F1_LEAK" -eq 0 ]  || fail "(a) 외부망에 평문이 보인다"
[ "$F1_IN" -eq 0 ]    || fail "(a) 복호화되지 않은 요청이 app 까지 갔다"

# (b) 클라이언트의 SA 도 삭제 — 보낼 때 쓸 SA 가 없다
ip -n client xfrm state flush
cap_start fault_client
F2=$(outcome 10.9.0.2 http://10.0.2.10:8080/)
cap_stop
F2_ESP=$(n_esp fault_client); F2_LEAK=$(n_leak fault_client); F2_IN=$(n_plain fault_client); F2_STAT=$(xstat client)
[ "$F2" != ALLOW ]    || fail "(b) SA 가 없는데 요청이 성공했다"
[ "$F2_LEAK" -eq 0 ]  || fail "(b) 외부망에 평문이 보인다 — 실패 시 열림"
[ "$F2_IN" -eq 0 ]    || fail "(b) 요청이 app 까지 갔다"

# ── 요약 (GitHub Actions 요약 화면에 그대로 붙인다) ──
{
  echo '## 연결 매트릭스'; cat "$OUT/matrix.md"; echo
  echo 'DROP = 시간 초과(패킷이 폐기됨), REFUSED = 연결 거부(포트가 닫힘). 정책이 차단하면 DROP 이어야 한다.'; echo
  echo '## 차단·허용 카운터 (게이트웨이 nftables)'
  echo '| 카운터 | 패킷 수 |'; echo '|---|---|'
  echo "| allow_app | $A |"; echo "| deny_no_tunnel | $N |"; echo "| deny_not_allowed | $D |"; echo
  echo "## 차단 로그 (건별): deny_no_tunnel ${L_N}줄, deny_not_allowed ${L_D}줄, 허용한 요청 ${L_ALLOWED}줄"
  echo 'deny_no_tunnel (IPsec 이 적용되지 않은 패킷)'
  echo '```'; head -8 "$OUT/drop_no_tunnel.txt"; echo '```'
  echo 'deny_not_allowed (터널로 들어왔지만 허용 목록에 없는 목적지)'
  echo '```'; head -8 "$OUT/drop_not_allowed.txt"; echo '```'
  echo "## 패킷 캡처: 외부망 (br0) — ESP ${ESP}개, 평문 노출 ${LEAK}개"
  echo '```'; head -8 "$OUT/capture_wan.txt"; echo '```'
  echo "## 패킷 캡처: 터널 안쪽 (gw-app) — 복호화된 요청 ${PLAIN}개"
  echo '```'; head -8 "$OUT/capture_inside.txt"; echo '```'
  echo '## 장애 실험: SA 삭제 (정책은 유지)'
  echo '| 상황 | 요청 결과 | 외부망 ESP | 외부망 평문 | app 도착 | 커널 xfrm 통계 (0 아닌 것) |'
  echo '|---|---|---|---|---|---|'
  echo "| (a) 게이트웨이 SA 삭제 | $F1 | $F1_ESP | $F1_LEAK | $F1_IN | gw: $F1_STAT |"
  echo "| (b) 클라이언트 SA 도 삭제 | $F2 | $F2_ESP | $F2_LEAK | $F2_IN | client: $F2_STAT |"
  echo
  echo '## IPsec SA (게이트웨이, 장애 실험 전, 키 생략)'
  echo '```'; cat "$OUT/xfrm_state.txt"; echo '```'
} > "$OUT/summary.md"
cat "$OUT/summary.md"

[ "$FAIL" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"
