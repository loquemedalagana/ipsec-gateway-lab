#!/usr/bin/env bash
# 비교 단계 전체 실행: kind 2노드 + Cilium(IPsec) 구성 → 캡처 → 연결 매트릭스 → 정리.
# run.sh(게이트웨이형)와 같은 질문을 쿠버네티스의 노드 간 투명 암호화에 던진다.
# 검사가 하나라도 어긋나면 0이 아닌 값으로 끝난다. 결과는 out-cilium/ 에 남는다.
# root 권한은 필요 없고 docker, kind, kubectl, cilium(cilium-cli)이 필요하다.
#   KEEP=1  끝난 뒤 클러스터를 남긴다 (cilium/check.sh 를 다시 돌려 볼 때)
set -euo pipefail
cd "$(dirname "$0")"

cilium/down.sh
[ "${KEEP:-0}" = 1 ] || trap cilium/down.sh EXIT
cilium/up.sh
cilium/check.sh
