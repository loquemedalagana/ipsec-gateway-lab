#!/usr/bin/env bash
# 네임스페이스 5개로 "클라이언트 — (외부망) — 게이트웨이 — 내부 서버 2대"를 만든다.
#
#   client ──[ net: br0 ]── gw ──(10.0.2.0/24)── app  :8080  허용 대상
#   10.0.1.2   외부망     10.0.1.1 └─(10.0.3.0/24)── db   :5432  차단 대상
#   터널 안 주소 10.9.0.2
#
# net 은 둘 사이의 "선" 역할만 하는 브리지다. 제3자가 보는 패킷을 여기서 캡처한다.
# client 와 gw 사이에는 IPsec ESP 터널 모드를 건다. SA 는 IKEv2(strongSwan)가 협상해서 넣는다.
set -euo pipefail

CLIENT_WAN=10.0.1.2   # 터널 바깥(외부) 주소
GW_WAN=10.0.1.1
CLIENT_VIP=10.9.0.2   # 터널 안에서 쓰는 주소
INSIDE=10.0.2.0/23    # 보호 대상 대역 (10.0.2.0/24 + 10.0.3.0/24)

for ns in client net gw app db; do
  ip netns add "$ns"
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  ip -n "$ns" link set lo up
done

# veth 한 쌍을 두 네임스페이스에 나눠 꽂는다: link <nsA> <ifA> <addrA> <nsB> <ifB> <addrB>
link() {
  ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
  ip -n "$1" addr add "$3" dev "$2"; ip -n "$1" link set "$2" up
  ip -n "$4" addr add "$6" dev "$5"; ip -n "$4" link set "$5" up
}
# 외부망: client 와 gw 를 net 의 브리지 br0 에 꽂는다
ip -n net link add br0 type bridge; ip -n net link set br0 up
ip link add wan0   netns client type veth peer name p-client netns net
ip link add gw-wan netns gw     type veth peer name p-gw     netns net
ip -n net link set p-client master br0 up
ip -n net link set p-gw     master br0 up
ip -n client addr add "$CLIENT_WAN/24" dev wan0;   ip -n client link set wan0 up
ip -n gw     addr add "$GW_WAN/24"     dev gw-wan; ip -n gw     link set gw-wan up
link gw     gw-app 10.0.2.1/24      app eth0   10.0.2.10/24
link gw     gw-db  10.0.3.1/24      db  eth0   10.0.3.20/24

# 라우팅
ip netns exec gw sysctl -qw net.ipv4.ip_forward=1
ip -n app route add default via 10.0.2.1
ip -n db  route add default via 10.0.3.1
ip -n client link add vip0 type dummy
ip -n client addr add "$CLIENT_VIP/32" dev vip0
ip -n client link set vip0 up
ip -n client route add "$INSIDE" via "$GW_WAN" src "$CLIENT_VIP"
ip -n gw route add "$CLIENT_VIP/32" via "$CLIENT_WAN"

# IPsec: 키와 SA 를 직접 넣지 않는다. client 와 gw 에 IKE 데몬(strongSwan charon)을 하나씩 띄워 협상하게 한다.
# 한 호스트에 데몬이 둘이라, 데몬이 쓰는 고정 경로를 네임스페이스마다 따로 보이게 한다.
#   /etc/strongswan.conf, /etc/swanctl  ← /etc/netns/<ns>/ 아래 것 (ip netns exec 가 자동으로 덮어 보여 준다)
#   /run (제어 소켓·PID·로그)            ← $RUN/<ns> (실행할 때 직접 마운트)
HERE=$(cd "$(dirname "$0")" && pwd)
RUN=/tmp/ipsec-gateway-lab
sw() { "$HERE/sw.sh" "$@"; }   # 데몬에 명령을 보낸다: sw <ns> <명령> [옵션...]
# 사전공유키(PSK): 실행할 때마다 새로 만들고 출력하지 않는다. 양쪽에 같은 값을 준다.
PSK="0x$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
for ns in client gw; do
  mkdir -p "$RUN/$ns" "/etc/netns/$ns/swanctl"
  cat > "/etc/netns/$ns/strongswan.conf" <<'CONF'
charon {
  load = random nonce openssl kernel-netlink socket-default vici   # 필요한 플러그인만
  install_routes = no            # 경로는 위에서 직접 넣었다
  filelog { log { path = /run/charon.log
                  flush_line = yes
                  default = 1 } }
}
swanctl { load = random openssl }
CONF
  # 연결 설정(저장소의 파일) + 이번 실행의 PSK
  { cat "$HERE/swanctl/$ns.conf"
    printf 'secrets { ike-lab {\n id-1 = client\n id-2 = gw\n secret = %s\n} }\n' "$PSK"
  } > "/etc/netns/$ns/swanctl/swanctl.conf"
  chmod 600 "/etc/netns/$ns/swanctl/swanctl.conf"
  ip netns exec "$ns" sh -c "mount --bind $RUN/$ns /run && exec /usr/lib/ipsec/charon" >/dev/null 2>&1 &
done
for ns in client gw; do
  for _ in $(seq 50); do [ -S "$RUN/$ns/charon.vici" ] && break; sleep 0.1; done
  sw "$ns" --load-all > "$RUN/$ns/swanctl.log" 2>&1 || { cat "$RUN/$ns/swanctl.log"; exit 1; }
done
# 첫 요청이 협상을 기다리지 않도록 터널을 미리 올린다: IKE SA(인증·키 교환) → CHILD SA(ESP 에 쓸 SA 한 쌍)
sw client --initiate --child inside >> "$RUN/client/swanctl.log" 2>&1 || { cat "$RUN/client/swanctl.log"; exit 1; }

# 게이트웨이 접근제어: 기본 거부 + 명시 허용
ip netns exec gw nft -f "$(dirname "$0")/policy.nft"

# 내부 서버. db 도 실제로 듣게 해서 "포트가 닫혀서"가 아니라 "정책이 막아서" 실패함을 보인다.
mkdir -p /tmp/ipsec-gateway-lab/www && echo "hello from inside" > /tmp/ipsec-gateway-lab/www/index.html
ip netns exec app python3 -m http.server 8080 --bind 10.0.2.10 -d /tmp/ipsec-gateway-lab/www >/dev/null 2>&1 &
ip netns exec db  python3 -m http.server 5432 --bind 10.0.3.20 -d /tmp/ipsec-gateway-lab/www >/dev/null 2>&1 &
sleep 1
echo "setup done"
