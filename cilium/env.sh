# up.sh / check.sh / down.sh 가 함께 쓰는 값. 직접 실행하지 않고 source 한다.
CLUSTER=ipsec-compare
CP=$CLUSTER-control-plane
WK=$CLUSTER-worker
CILIUM_VERSION=${CILIUM_VERSION:-1.20.1}
TOOLS=${TOOLS:-nicolaka/netshoot}   # tcpdump 가 들어 있는 이미지. 노드의 네트워크 네임스페이스에 붙여서 캡처한다

# 전용 kubeconfig 를 쓴다. ~/.kube/config 와 현재 컨텍스트를 바꾸지 않으므로
# 같은 컴퓨터의 다른 클러스터 작업에 영향을 주지 않는다.
export KUBECONFIG=${TMPDIR:-/tmp}/ipsec-gateway-lab-cilium.kubeconfig
