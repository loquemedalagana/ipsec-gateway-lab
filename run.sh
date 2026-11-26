#!/usr/bin/env bash
# 전체 실행: 구성(IKE 협상) → 패킷 캡처 → 연결 매트릭스 → 차단 기록(카운터·건별 로그) → 키 교체 → 장애 실험 → 정리.
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
RUN=/tmp/ipsec-gateway-lab
sw() { lab/sw.sh "$@"; }   # IKE 데몬에 명령을 보낸다: sw <ns> <명령> [옵션...]
spis() { ip -n "$1" xfrm state | awk '$1=="proto" {print $4}' | sort | tr '\n' ' '; }   # 커널에 있는 SA 의 SPI 목록

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
# 캡처를 끌 때는 캡처 프로세스만 끈다(gw 에는 IKE 데몬도 돌고 있다)
cap_start() { # cap_start <파일 이름 앞부분>
  ip netns exec net tcpdump -i br0    -n -l > "$OUT/$1_wan.txt"    2>/dev/null & CAP_PIDS="$!"
  ip netns exec gw  tcpdump -i gw-app -n -l > "$OUT/$1_inside.txt" 2>/dev/null & CAP_PIDS="$CAP_PIDS $!"
  sleep 1
}
cap_stop() { sleep 1; kill $CAP_PIDS; sleep 0.5; }
n_esp()   { grep -c 'ESP(spi=' "$OUT/$1_wan.txt" || true; }                       # 외부망의 ESP 패킷 수
n_leak()  { grep -c -e '10\.9\.0\.2' -e '\.8080' "$OUT/$1_wan.txt" || true; }     # 외부망에 평문으로 보인 수
n_plain() { grep -c '> 10\.0\.2\.10\.8080' "$OUT/$1_inside.txt" || true; }        # app 에 도착한 요청 패킷 수
n_ike()   { grep -c 'isakmp' "$OUT/$1_wan.txt" || true; }                         # 외부망의 IKE 메시지 수 (UDP 500)
# 게이트웨이가 차단한 패킷의 건별 로그: nftables 가 nflog 그룹으로 보낸 것을 이유별 파일로 받는다
log_start() {
  ip netns exec gw tcpdump -i nflog:1 -n -l > "$OUT/drop_no_tunnel.txt"   2>/dev/null & LOG_PIDS="$!"
  ip netns exec gw tcpdump -i nflog:2 -n -l > "$OUT/drop_not_allowed.txt" 2>/dev/null & LOG_PIDS="$LOG_PIDS $!"
  sleep 1
}
log_stop() { sleep 1; kill $LOG_PIDS; sleep 0.5; }
n_log() { grep -c -E "$2" "$OUT/$1.txt" || true; }   # n_log <파일 이름> <정규식>: 맞는 로그 줄 수
xstat()   { ip netns exec "$1" cat /proc/net/xfrm_stat | awk '$2>0 {printf "%s=%s ", $1, $2} END {print ""}'; }

# ── 0. IKE: 양쪽 데몬이 서로를 인증하고 SA 를 협상해 커널에 넣었는지 ──
{ echo '# client'; sw client --list-sas; echo; echo '# gw'; sw gw --list-sas; } > "$OUT/ike_sas.txt"
IKE_C=$(sw client --list-sas | grep -c 'ESTABLISHED, IKEv2' || true)
IKE_G=$(sw gw     --list-sas | grep -c 'ESTABLISHED, IKEv2' || true)
SPI_C=$(spis client); SPI_G=$(spis gw)
[ "$IKE_C" -eq 1 ] && [ "$IKE_G" -eq 1 ] || fail "IKE SA 가 수립되지 않았다 (client=$IKE_C gw=$IKE_G)"
[ "$(echo $SPI_C | wc -w)" -eq 2 ]       || fail "커널의 SA 가 방향별 하나씩(2개)이 아니다: $SPI_C"
[ "$SPI_C" = "$SPI_G" ]                  || fail "양쪽 커널의 SPI 가 다르다 (client: $SPI_C / gw: $SPI_G)"

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

# ── 4. 키 교체(rekey): 새 키로 바꿔도 통신이 이어지는가 ──
# 수동 키에서는 할 수 없던 일이다. CHILD SA 를 다시 협상시키고, SPI 가 바뀌었는지와 요청이 여전히 되는지를 본다.
SPI_OLD=$(spis client)
cap_start rekey
sw client --rekey --child inside > "$OUT/ike_rekey.txt" 2>&1 || fail "rekey 명령 실패"
sleep 1
RK=$(outcome 10.9.0.2 http://10.0.2.10:8080/)
cap_stop
SPI_NEW=$(for x in $(spis client); do echo " $SPI_OLD" | grep -q " $x " || printf '%s ' "$x"; done)   # 이전 목록에 없던 SPI
RK_IKE=$(n_ike rekey); RK_LEAK=$(n_leak rekey)
[ "$RK" = ALLOW ]                        || fail "키 교체 뒤 요청이 실패했다 ($RK)"
[ "$(echo $SPI_NEW | wc -w)" -eq 2 ]     || fail "키 교체 뒤 새 SPI 가 방향별 하나씩 생기지 않았다 (이전: $SPI_OLD / 새로 생긴 것: $SPI_NEW)"
[ "$RK_IKE" -gt 0 ]                      || fail "외부망에 IKE 메시지가 보이지 않는다"
[ "$RK_LEAK" -eq 0 ]                     || fail "키 교체 중 외부망에 평문이 보인다"

# ── 5. ARP 스푸핑 관찰: 경로에 끼어든 공격자가 무엇을 보는가 ──
# attacker 는 외부망 브리지(br0)에 함께 꽂혀 있다. 스위치라서 평소에는 client↔gw 유니캐스트가
# attacker 에게 가지 않는다. 아래 arp_spoof_start 에 거짓 ARP 를 보내는 명령을 직접 채우면,
# 상대의 ARP 캐시가 공격자의 MAC 으로 바뀌어 트래픽이 attacker 를 거친다.
# 채우기 전에는(ARP_SPOOF_READY=0) 판정을 건너뛴다 — 비어 있어도 CI 가 깨지지 않도록.
ARP_SPOOF_READY=1

arp_spoof_start() {
  # client(10.0.1.2) ↔ gw(10.0.1.1) 양방향 ARP 스푸핑
  ip netns exec attacker arpspoof -i atk0 -t 10.0.1.2 -r 10.0.1.1 >/dev/null 2>&1 &
  ARP_PID=$!
}

arp_spoof_stop() {
  if [ -n "${ARP_PID:-}" ]; then
    kill -INT "$ARP_PID" 2>/dev/null || true
    wait "$ARP_PID" 2>/dev/null || true
    unset ARP_PID
  fi
  # 다음 단계(5-1, 6)에 영향이 없도록 양쪽 ARP 캐시 초기화
  ip -n client neigh flush dev wan0 2>/dev/null || true
  ip -n gw     neigh flush all      2>/dev/null || true
}

# attacker 쪽 캡처: 공격자가 자기 인터페이스에서 실제로 무엇을 보는지
atk_cap_start() { ip netns exec attacker tcpdump -i atk0 -n -l > "$OUT/$1_atk.txt" 2>/dev/null & ATK_PID="$!"; sleep 1; }
atk_cap_stop()  { sleep 1; kill "$ATK_PID" 2>/dev/null || true; sleep 0.5; }
n_atk_esp()  { grep -c 'ESP(spi=' "$OUT/$1_atk.txt" || true; }                    # 공격자가 본 ESP
n_atk_leak() { grep -c -e '10\.9\.0\.2' -e '\.8080' "$OUT/$1_atk.txt" || true; }  # 공격자가 본 터널 안 평문

# client 가 아는 gw(10.0.1.1)의 MAC. 주소로 필터하면 'dev' 가 빠져 필드가 당겨지므로 lladdr 다음 값을 집는다.
gw_mac_at_client() { ip -n client neigh show 10.0.1.1 dev wan0 | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}'; }
# 위조는 2초 간격으로 나가므로 한 번만 읽으면 주기와 어긋나 놓칠 수 있다.
# 캐시가 바뀔 때까지 최대 ~8초, 0.5초마다 확인하고 바뀌면 즉시 반환한다(시간 초과 시 마지막 값).
wait_mac_change() {  # wait_mac_change <기준 MAC>
  local base="$1" cur=""
  for _ in $(seq 16); do
    cur=$(gw_mac_at_client)
    [ -n "$cur" ] && [ "$cur" != "$base" ] && { echo "$cur"; return; }
    sleep 0.5
  done
  echo "$cur"
}
ARP_BEFORE=$(gw_mac_at_client)        # 공격 전
arp_spoof_start
ARP_AFTER=$(wait_mac_change "$ARP_BEFORE")   # 위조가 캐시를 덮을 때까지 기다린다

# 1) 실험군: 터널 요청만 캡처 (암호문 ESP만 보여야 함)
atk_cap_start arp_tunnel
ARP_S1=$(outcome 10.9.0.2 http://10.0.2.10:8080/)
atk_cap_stop

# 2) 대조군: 터널 없는 요청만 캡처 (평문이 보여야 함)
atk_cap_start arp_plain
ARP_S2=$(outcome 10.0.1.2 http://10.0.2.10:8080/)
atk_cap_stop

arp_spoof_stop

ARP_ESP=$(n_atk_esp arp_tunnel)
ARP_LEAK=$(n_atk_leak arp_tunnel)
ARP_PLAIN_SEEN=$(n_atk_leak arp_plain)

if [ "$ARP_SPOOF_READY" -eq 1 ]; then
  [ -n "$ARP_AFTER" ] && [ "$ARP_AFTER" != "$ARP_BEFORE" ] || fail "(ARP) client 의 캐시가 공격자 MAC 으로 바뀌지 않았다 ($ARP_BEFORE → $ARP_AFTER)"
  [ "$ARP_ESP" -gt 0 ]        || fail "(ARP) 공격자가 경로에 있는데 ESP 가 보이지 않는다"
  [ "$ARP_LEAK" -eq 0 ]       || fail "(ARP) 공격자에게 터널 안 주소·포트가 평문으로 보인다 — 기밀성 깨짐"
  [ "$ARP_PLAIN_SEEN" -gt 0 ] || fail "(ARP) 대조군(터널 없는 요청)의 평문이 공격자에게 보이지 않는다"

  # ── 5-1. 정적 ARP 대응 검증 (static ARP 등록 후 재공격 시 MAC 유지 확인) ──
  ip -n client neigh replace 10.0.1.1 lladdr "$ARP_BEFORE" dev wan0 nud permanent
  arp_spoof_start
  sleep 4            # 위조가 두 주기는 시도하도록 기다린 뒤, 그래도 안 바뀌었는지 본다(바뀌면 안 됨)
  ARP_STATIC=$(gw_mac_at_client)
  arp_spoof_stop

  [ "$ARP_STATIC" = "$ARP_BEFORE" ] || fail "(ARP 대응) 정적 ARP를 걸었는데 MAC이 변조됐다 ($ARP_BEFORE → $ARP_STATIC)"

  # 6단계 장애 실험을 위해 정적 엔트리 제거(동적 상태로 복구)
  ip -n client neigh del 10.0.1.1 dev wan0 2>/dev/null || true

  ARP_NOTE="동적 변조 확인($ARP_BEFORE → $ARP_AFTER), 대조군 평문 ${ARP_PLAIN_SEEN}개 노출 / 정적 ARP 대응 시 MAC 유지($ARP_STATIC)"
else
  ARP_NOTE="미구현 — run.sh 의 arp_spoof_start/stop 을 채우고 ARP_SPOOF_READY=1 로 바꾸면 판정이 켜진다"
fi

# ── 6. 장애 실험: SA 가 사라지면 요청은 평문으로 새는가, 막히는가 ──
# 커널의 SA 만 지운다(정책은 그대로). 기대: 요청은 실패하고, 평문은 어디에도 나가지 않는다.
# IKE 데몬은 커널에서 SA 가 지워진 것을 모른다. 그래서 데몬이 있어도 저절로 복구되지 않는다.
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
F2_DAEMON=$(sw client --list-sas | grep -c 'INSTALLED' || true)   # 데몬은 SA 가 아직 있다고 본다

# (c) 복구 — IKE SA 를 끊는다. 걸어 둔 정책(trap)이 남아 있어서, 다음 요청이 오면 데몬이 처음부터 다시 협상한다
sw client --terminate --ike gw > "$OUT/ike_terminate.txt" 2>&1 || true
cap_start recover
F3=$(outcome 10.9.0.2 http://10.0.2.10:8080/)
cap_stop
F3_ESP=$(n_esp recover); F3_LEAK=$(n_leak recover); F3_IN=$(n_plain recover); F3_IKE=$(n_ike recover)
[ "$F3" = ALLOW ]     || fail "(c) 다시 협상한 뒤에도 요청이 실패했다 ($F3)"
[ "$F3_IKE" -gt 0 ]   || fail "(c) 외부망에 재협상(IKE)이 보이지 않는다"
[ "$F3_LEAK" -eq 0 ]  || fail "(c) 재협상 중 외부망에 평문이 보인다"

# (d) 인증 실패 — 클라이언트의 사전공유키를 다른 값으로 바꾸고 다시 협상하게 한다
# 기대: 게이트웨이가 인증을 거부해 SA 가 생기지 않고, 요청은 평문으로 나가지 않고 버려진다.
sw client --terminate --ike gw >> "$OUT/ike_terminate.txt" 2>&1 || true
printf 'secrets { ike-lab {\n id-1 = client\n id-2 = gw\n secret = 0x%s\n} }\n' "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')" \
  > /etc/netns/client/swanctl/wrong.conf
sw client --load-creds --clear --file /etc/swanctl/wrong.conf > /dev/null 2>&1 || fail "(d) 키를 바꿔 넣지 못했다"
cap_start fault_psk
F4=$(outcome 10.9.0.2 http://10.0.2.10:8080/)
cap_stop
F4_ESP=$(n_esp fault_psk); F4_LEAK=$(n_leak fault_psk); F4_IN=$(n_plain fault_psk); F4_IKE=$(n_ike fault_psk)
F4_AUTH=$(grep -c 'AUTHENTICATION_FAILED' "$RUN/client/charon.log" || true)
F4_SA=$(sw client --list-sas | grep -c 'ESTABLISHED' || true)
[ "$F4" != ALLOW ]    || fail "(d) 키가 틀린데 요청이 성공했다"
[ "$F4_AUTH" -gt 0 ]  || fail "(d) 인증 실패 기록이 없다"
[ "$F4_SA" -eq 0 ]    || fail "(d) 키가 틀린데 IKE SA 가 수립됐다"
[ "$F4_ESP" -eq 0 ]   || fail "(d) SA 가 없는데 외부망에 ESP 가 보인다"
[ "$F4_LEAK" -eq 0 ]  || fail "(d) 외부망에 평문이 보인다 — 실패 시 열림"
[ "$F4_IN" -eq 0 ]    || fail "(d) 요청이 app 까지 갔다"

# IKE 데몬 로그를 증거로 남긴다(로그 수준 1: 키는 찍히지 않는다)
cp "$RUN/client/charon.log" "$OUT/ike_client.log"; cp "$RUN/gw/charon.log" "$OUT/ike_gw.log"

# ── 요약 (GitHub Actions 요약 화면에 그대로 붙인다) ──
{
  echo '## IKE 협상 (strongSwan, IKEv2, 사전공유키)'
  echo "IKE SA 수립: client ${IKE_C}개, gw ${IKE_G}개. 커널의 SPI(양쪽 동일): \`${SPI_C% }\`"
  echo '```'; sed -n '/^# gw/,$p' "$OUT/ike_sas.txt"; echo '```'
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
  echo '## 키 교체 (rekey)'
  echo "요청 결과 $RK, 외부망 IKE 메시지 ${RK_IKE}개, 외부망 평문 ${RK_LEAK}개"; echo
  echo "| | SPI |"; echo '|---|---|'
  echo "| 교체 전 | \`${SPI_OLD% }\` |"; echo "| 새로 생긴 것 | \`${SPI_NEW% }\` |"; echo
  echo '외부망에서 본 IKE 메시지 (내용은 암호화되어 종류만 보인다)'
  echo '```'; grep 'isakmp' "$OUT/rekey_wan.txt" | head -4; echo '```'
  echo '## ARP 스푸핑 관찰 (온패스 공격자)'
  echo "| 항목 | 값 |"; echo '|---|---|'
  echo "| 터널 요청(공격자 경유) | $ARP_S1 |"
  echo "| 대조군: 터널 없는 요청 | $ARP_S2 |"
  echo "| 공격자가 본 ESP | ${ARP_ESP}개 |"
  echo "| 공격자가 본 터널 안 평문 | ${ARP_LEAK}개 |"
  echo "| 상태 | $ARP_NOTE |"; echo
  echo '## 장애 실험: SA 삭제 → 복구 → 인증 실패'
  echo '| 상황 | 요청 결과 | 외부망 ESP | 외부망 평문 | app 도착 | 비고 |'
  echo '|---|---|---|---|---|---|'
  echo "| (a) 게이트웨이의 커널 SA 삭제 | $F1 | $F1_ESP | $F1_LEAK | $F1_IN | gw 커널 통계: $F1_STAT |"
  echo "| (b) 클라이언트의 커널 SA 도 삭제 | $F2 | $F2_ESP | $F2_LEAK | $F2_IN | client 커널 통계: $F2_STAT / 데몬이 아는 SA: ${F2_DAEMON}개 |"
  echo "| (c) IKE SA 를 끊고 다시 요청 | $F3 | $F3_ESP | $F3_LEAK | $F3_IN | 외부망 IKE 메시지 ${F3_IKE}개 (재협상) |"
  echo "| (d) 사전공유키 불일치 | $F4 | $F4_ESP | $F4_LEAK | $F4_IN | 외부망 IKE 메시지 ${F4_IKE}개, 인증 실패 기록 ${F4_AUTH}건 |"
  echo
  echo '## IPsec SA (게이트웨이, 키 교체·장애 실험 전, 키 생략)'
  echo '```'; cat "$OUT/xfrm_state.txt"; echo '```'
} > "$OUT/summary.md"
cat "$OUT/summary.md"

[ "$FAIL" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"
