#!/usr/bin/env bash
# 이 실습이 만든 것만 지운다: 캡처용 컨테이너, kind 클러스터 ipsec-compare, 전용 kubeconfig.
set -uo pipefail
cd "$(dirname "$0")"
. ./env.sh
docker ps -aq --filter "name=^$CLUSTER-cap-" | xargs -r docker rm -f >/dev/null 2>&1
kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" 2>&1 | grep -v '^$' || true
rm -f "$KUBECONFIG"
