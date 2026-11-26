#!/usr/bin/env bash
# 네임스페이스 안의 IKE 데몬에 swanctl 명령을 보낸다: lab/sw.sh <ns> <명령> [옵션...]
#   예) lab/sw.sh client --list-sas
# 데몬과 같은 /run(제어 소켓이 있는 곳)과 /etc/swanctl 을 보도록 그 네임스페이스로 들어가서 실행한다.
exec ip netns exec "$1" sh -c 'mount --bind "$0" /run && exec swanctl "$@"' "/tmp/ipsec-gateway-lab/$1" "${@:2}"
