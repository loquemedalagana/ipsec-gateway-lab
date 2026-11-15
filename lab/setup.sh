#!/usr/bin/env bash
# 네임스페이스 5개로 "클라이언트 — (외부망) — 게이트웨이 — 내부 서버 2대"를 만든다.
#
#   client ──[ net: br0 ]── gw ──(10.0.2.0/24)── app  :8080  허용 대상
#   10.0.1.2   외부망     10.0.1.1 └─(10.0.3.0/24)── db   :5432  차단 대상
#   터널 안 주소 10.9.0.2
#
# net 은 둘 사이의 "선" 역할만 하는 브리지다. 제3자가 보는 패킷을 여기서 캡처한다.
# client 와 gw 사이에는 IPsec ESP 터널 모드를 건다(수동 SA, IKE 없음).
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

# IPsec SA(보안 연관): 방향마다 하나씩. 키는 실행할 때마다 새로 만들고 출력하지 않는다.
# AES-GCM: 키 16바이트 + salt 4바이트 = 20바이트, 무결성 값(ICV) 128비트
key() { echo "0x$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n')"; }
K_C2G=$(key); K_G2C=$(key)
for ns in client gw; do
  ip -n "$ns" xfrm state add src "$CLIENT_WAN" dst "$GW_WAN" proto esp spi 0x1001 reqid 1 replay-window 32 \
    mode tunnel aead 'rfc4106(gcm(aes))' "$K_C2G" 128
  ip -n "$ns" xfrm state add src "$GW_WAN" dst "$CLIENT_WAN" proto esp spi 0x1002 reqid 1 replay-window 32 \
    mode tunnel aead 'rfc4106(gcm(aes))' "$K_G2C" 128
done

# IPsec SP(보안 정책): 어떤 패킷을 터널에 넣을지. 터널 안 주소 ↔ 보호 대역만 해당한다.
C2G="tmpl src $CLIENT_WAN dst $GW_WAN proto esp reqid 1 mode tunnel"
G2C="tmpl src $GW_WAN dst $CLIENT_WAN proto esp reqid 1 mode tunnel"
ip -n client xfrm policy add src "$CLIENT_VIP/32" dst "$INSIDE" dir out $C2G
ip -n client xfrm policy add src "$INSIDE" dst "$CLIENT_VIP/32" dir in  $G2C
ip -n gw     xfrm policy add src "$CLIENT_VIP/32" dst "$INSIDE" dir fwd $C2G
ip -n gw     xfrm policy add src "$INSIDE" dst "$CLIENT_VIP/32" dir out $G2C

# 게이트웨이 접근제어: 기본 거부 + 명시 허용
ip netns exec gw nft -f "$(dirname "$0")/policy.nft"

# 내부 서버. db 도 실제로 듣게 해서 "포트가 닫혀서"가 아니라 "정책이 막아서" 실패함을 보인다.
mkdir -p /tmp/netns-vpn-lab/www && echo "hello from inside" > /tmp/netns-vpn-lab/www/index.html
ip netns exec app python3 -m http.server 8080 --bind 10.0.2.10 -d /tmp/netns-vpn-lab/www >/dev/null 2>&1 &
ip netns exec db  python3 -m http.server 5432 --bind 10.0.3.20 -d /tmp/netns-vpn-lab/www >/dev/null 2>&1 &
sleep 1
echo "setup done"
