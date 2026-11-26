#!/usr/bin/env bash
# 네임스페이스를 지우면 그 안의 인터페이스·SA·nft 규칙·프로세스 소켓도 함께 사라진다.
for ns in client net gw app db attacker; do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del "$ns" 2>/dev/null
done
rm -rf /tmp/ipsec-gateway-lab /etc/netns/client /etc/netns/gw   # IKE 데몬의 소켓·로그, 네임스페이스별 설정
exit 0
