#!/usr/bin/env bash
# 검사: 노드 사이 캡처 → 같은 노드 캡처 → 연결 매트릭스.
# 검사가 하나라도 어긋나면 0이 아닌 값으로 끝난다. 결과는 out-cilium/ 에 남는다.
# up.sh 로 클러스터가 올라와 있어야 한다.
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh
OUT=../out-cilium; rm -rf "$OUT"; mkdir -p "$OUT"
FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }

APP_IP=$(kubectl -n lab get pod app -o jsonpath='{.status.podIP}')
node_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
CP_IP=$(node_ip "$CP"); WK_IP=$(node_ip "$WK")

# 요청 한 번을 보내고 결과를 한 단어로 돌려준다: outcome <파드> <url>
#   ALLOW   = 응답을 받음
#   DROP    = 시간 초과(curl 28). 패킷이 조용히 버려졌다 → 정책이 막은 것
#   REFUSED = 연결 거부(curl 7). 서버까지 갔는데 포트가 닫혀 있다 → 정책이 막은 것이 아님
outcome() {
  local rc=0
  kubectl -n lab exec "$1" -- curl -s -o /dev/null --max-time 2 "$2" >/dev/null 2>&1 || rc=$?
  case $rc in 0) echo ALLOW;; 28) echo DROP;; 7) echo REFUSED;; *) echo "ERR($rc)";; esac
}
check() { # check <설명> <기대값> <파드> <url>
  local got mark=ok; got=$(outcome "$3" "$4")
  [ "$got" = "$2" ] || { mark=MISMATCH; FAIL=1; }
  printf '| %s | %s | %s | %s |\n' "$1" "$2" "$got" "$mark" | tee -a "$OUT/matrix.md"
}

# 노드의 네트워크 네임스페이스에 컨테이너를 붙여 캡처한다: cap_start <파일 이름> <노드> <tcpdump 인자…>
# -A 로 내용까지 남겨서, 요청 경로에 넣은 마커 문자열이 평문으로 보이는지 센다.
cap_start() {
  local name=$1 node=$2; shift 2
  docker run -d --name "$CLUSTER-cap-$name" --net "container:$node" --cap-add NET_ADMIN --cap-add NET_RAW \
    "$TOOLS" tcpdump -nn -l -A "$@" >/dev/null
}
cap_stop() { # cap_stop <파일 이름…>
  local n; sleep 1
  for n in "$@"; do
    docker stop -t 3 "$CLUSTER-cap-$n" >/dev/null
    docker logs "$CLUSTER-cap-$n" > "$OUT/$n.txt" 2>/dev/null
    docker rm "$CLUSTER-cap-$n" >/dev/null
  done
}
count()   { grep -c -e "$1" "$OUT/$2.txt" || true; }   # count <패턴> <파일 이름>
n_esp()   { count 'ESP(spi=' "$1"; }
# 노드 간 구간에 평문으로 보인 줄 수: 마커 문자열, app 파드 주소, 포트 8080
n_leak()  { grep -c -e "$2" -e "${APP_IP//./\\.}\\." -e '\.8080[: ]' "$OUT/$1.txt" || true; }

# ── 0. 암호화 상태: IPsec 이 켜져 있는지 에이전트에게 묻는다 ──
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg encrypt status > "$OUT/encrypt_status.txt" 2>&1 || true
ENC=$(awk '/^Encryption/ {print $2}' "$OUT/encrypt_status.txt")
[ "$ENC" = IPsec ] || fail "Cilium 암호화가 IPsec 이 아니다 (현재: ${ENC:-알 수 없음})"

# ── 1. 다른 노드의 파드 사이: client-remote(control-plane) → app(worker) ──
# 송신 노드의 eth0 에서 egress(송신) 방향만 캡처한다. 수신 노드에서 캡처하면 복호화된 패킷도 함께 보이기 때문이다.
# 같은 요청을 수신 노드 내부(파드로 가는 구간)에서도 캡처한다.
M1="/cross-$RANDOM$RANDOM"
cap_start cross_wire   "$CP" -i eth0 -Q out "host $WK_IP"
cap_start cross_inside "$WK" -i any "tcp port 8080"
sleep 2
[ "$(outcome client-remote "http://$APP_IP:8080$M1")" = ALLOW ] || fail "다른 노드로 가는 요청 실패"
cap_stop cross_wire cross_inside
X_ESP=$(n_esp cross_wire); X_LEAK=$(n_leak cross_wire "$M1"); X_PLAIN=$(count "$M1" cross_inside)
[ "$X_ESP" -gt 0 ]   || fail "노드 간 구간에 ESP 패킷이 없다"
[ "$X_LEAK" -eq 0 ]  || fail "노드 간 구간에 파드 주소·포트·요청 내용이 평문으로 보인다"
[ "$X_PLAIN" -gt 0 ] || fail "수신 노드 내부에서 복호화된 요청이 보이지 않는다"

# ── 2. 같은 노드의 파드 사이: client-local(worker) → app(worker) ──
# 기대: 노드 내부에서는 요청이 평문으로 보이고, eth0 에는 이 요청이 아예 나가지 않는다.
M2="/same-$RANDOM$RANDOM"
cap_start same_wire   "$WK" -i eth0
cap_start same_inside "$WK" -i any "tcp port 8080"
sleep 2
[ "$(outcome client-local "http://$APP_IP:8080$M2")" = ALLOW ] || fail "같은 노드 안의 요청 실패"
cap_stop same_wire same_inside
S_ESP=$(n_esp same_wire); S_LEAK=$(n_leak same_wire "$M2"); S_PLAIN=$(count "$M2" same_inside)
[ "$S_PLAIN" -gt 0 ] || fail "같은 노드 내부에서 평문 요청이 보이지 않는다"
[ "$S_LEAK" -eq 0 ]  || fail "같은 노드 요청이 eth0 에 보인다"

# ── 3. 연결 매트릭스: 암호화를 켠 상태에서 허용해야 할 쌍과 막아야 할 쌍을 모두 검사한다 ──
# 차단이 이유와 함께 기록되는지도 본다: app 이 있는 worker 노드 에이전트의 "Policy denied" 폐기 수
WK_AGENT=$(kubectl -n kube-system get pod -l k8s-app=cilium --field-selector "spec.nodeName=$WK" -o name)
denied() {
  kubectl -n kube-system exec "$WK_AGENT" -c cilium-agent -- cilium-dbg metrics list 2>/dev/null \
    | awk '$1=="cilium_drop_count_total" && /direction=INGRESS/ && /reason=Policy denied/ {n=int($NF)} END {print n+0}'
}
D0=$(denied)
{ echo '| 경로 | 기대 | 결과 | 판정 |'; echo '|---|---|---|---|'; } | tee "$OUT/matrix.md"
check 'client(다른 노드) → app:8080'       ALLOW client-remote "http://$APP_IP:8080/"
check 'client(같은 노드) → app:8080'       ALLOW client-local  "http://$APP_IP:8080/"
check 'client → app:9090 (허용 외 포트)'   DROP  client-remote "http://$APP_IP:9090/"
check 'other → app:8080 (허용 외 파드)'    DROP  other         "http://$APP_IP:8080/"
D1=$(denied)
[ "$D1" -gt "$D0" ] || fail "정책 차단이 기록되지 않았다 (Policy denied $D0 → $D1)"

# SA 는 키를 지우고 남긴다
docker exec "$WK" ip xfrm state | sed -E 's/0x[0-9a-f]{16,}/(key 생략)/' > "$OUT/xfrm_state.txt" || true
N_SA=$(grep -c '^src ' "$OUT/xfrm_state.txt" || true)
# 남긴 파일에 키처럼 보이는 긴 16진수가 있으면 실패로 처리한다
if grep -rqE '(0x)?[0-9a-f]{40,}' "$OUT"; then fail "결과 파일에 키처럼 보이는 값이 있다"; fi

# ── 요약 (GitHub Actions 요약 화면에 그대로 붙인다) ──
# 캡처에서 요청 한 건의 머리줄과 마커이 들어 있는 줄만 뽑는다: req_lines <파일 이름> <마커>
req_lines() { { grep -m1 -E '\.8080: Flags \[P' "$OUT/$1.txt"; grep -m1 -o "GET $2 HTTP/1.1" "$OUT/$1.txt"; } | cut -c1-120 || true; }
{
  echo "## Cilium IPsec 비교 단계"
  echo "Cilium $CILIUM_VERSION, 암호화: ${ENC:-없음}, 노드 control-plane=$CP_IP worker=$WK_IP, app 파드=$APP_IP (worker)"; echo
  echo '## 연결 매트릭스'; cat "$OUT/matrix.md"; echo
  echo 'DROP = 시간 초과(패킷이 폐기됨), REFUSED = 연결 거부(포트가 닫힘). 정책이 차단하면 DROP 이어야 한다.'; echo
  echo '## 캡처 요약'
  echo '| 요청 | 노드 간 구간(eth0) ESP | 노드 간 구간 평문 노출 | 노드 내부에서 보인 평문 요청 |'
  echo '|---|---|---|---|'
  echo "| 다른 노드 (client-remote → app) | $X_ESP | $X_LEAK | $X_PLAIN |"
  echo "| 같은 노드 (client-local → app) | $S_ESP | $S_LEAK | $S_PLAIN |"; echo
  echo '같은 노드 행의 ESP 는 판정에 쓰지 않는다. 노드끼리 주고받는 다른 통신이 캡처 시간에 겹치면 0이 아닐 수 있다.'; echo
  echo '## 차단 기록 (worker 노드 Cilium 에이전트)'
  echo '| 통계 | 매트릭스 전 | 매트릭스 후 |'; echo '|---|---|---|'
  echo "| cilium_drop_count_total, INGRESS, Policy denied | $D0 | $D1 |"; echo
  echo "## 다른 노드: 송신 노드의 eth0, egress 방향 — ESP ${X_ESP}개, 평문 노출 ${X_LEAK}개"
  echo '```'; grep 'ESP(spi=' "$OUT/cross_wire.txt" | head -6 || true; echo '```'
  echo "## 다른 노드: 수신 노드 내부 — 복호화된 요청"
  echo '```'; req_lines cross_inside "$M1"; echo '```'
  echo "## 같은 노드: 노드 내부 — 평문 요청 (eth0 에는 0개)"
  echo '```'; req_lines same_inside "$M2"; echo '```'
  echo "## IPsec SA (worker 노드, ${N_SA}개, 키 생략)"
  echo '```'; grep -E '^src |proto esp|aead ' "$OUT/xfrm_state.txt" || true; echo '```'
} > "$OUT/summary.md"
cat "$OUT/summary.md"

[ "$FAIL" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"
