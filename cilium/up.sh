#!/usr/bin/env bash
# kind 2노드 클러스터를 만들고 Cilium 을 IPsec 을 켠 채로 설치한 뒤, 파드와 정책을 올린다.
# 필요한 것: docker, kind, kubectl, cilium(cilium-cli)
#   ENCRYPT=0  IPsec 을 끄고 설치한다. 검사가 실패로 끝나는지 확인할 때만 쓴다.
#   NEED_MB    Docker 에 남아 있어야 하는 메모리(MiB). 기본 3000
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

for t in docker kind kubectl cilium; do
  command -v "$t" >/dev/null || { echo "필요한 도구가 없다: $t"; exit 1; }
done

# 메모리가 모자라면 올리지 않는다. Docker(리눅스 VM) 안에서 보이는 여유를 기준으로 한다.
NEED_MB=${NEED_MB:-3000}
AVAIL_MB=$(docker run --rm "$TOOLS" awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
echo "Docker 메모리 여유: ${AVAIL_MB}MiB (필요 ${NEED_MB}MiB)"
[ "$AVAIL_MB" -ge "$NEED_MB" ] || { echo "메모리가 부족해서 클러스터를 올리지 않는다"; exit 1; }

kind create cluster --name "$CLUSTER" --config kind.yaml --kubeconfig "$KUBECONFIG"

FLAGS=(--set kubeProxyReplacement=true --set k8sServiceHost="$CP" --set k8sServicePort=6443
       --set operator.replicas=1 --set envoy.enabled=false --set hubble.enabled=false)
if [ "${ENCRYPT:-1}" = 1 ]; then
  # IPsec 키: 실행할 때마다 새로 만들고, 화면·파일·명령 인자에 남기지 않는다(표준 입력으로 Secret 에 넣는다).
  # 형식: "<키 번호>+ <알고리즘> <키> <ICV 비트>". AES-GCM 키 16바이트 + salt 4바이트 = 20바이트.
  # '+' 는 이 키에서 노드 쌍마다 다른 키를 파생하라는 뜻이다.
  printf '3+ rfc4106(gcm(aes)) %s 128' "$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n')" \
    | kubectl -n kube-system create secret generic cilium-ipsec-keys --from-file=keys=/dev/stdin >/dev/null
  FLAGS+=(--set encryption.enabled=true --set encryption.type=ipsec)
else
  echo "ENCRYPT=0: IPsec 을 끄고 설치한다 (검사는 실패해야 한다)"
fi
cilium install --version "$CILIUM_VERSION" "${FLAGS[@]}"
cilium status --wait --wait-duration 8m

kubectl apply -f workloads.yaml
kubectl -n lab wait --for=condition=Ready pod --all --timeout=240s
kubectl apply -f policy.yaml
sleep 5   # 정책이 각 노드의 에이전트에 반영될 시간
echo "up done"
