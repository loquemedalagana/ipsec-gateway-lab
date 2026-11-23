# ipsec-gateway-lab

[![lab](https://github.com/loquemedalagana/ipsec-gateway-lab/actions/workflows/lab.yml/badge.svg)](https://github.com/loquemedalagana/ipsec-gateway-lab/actions/workflows/lab.yml) [![cilium](https://github.com/loquemedalagana/ipsec-gateway-lab/actions/workflows/cilium.yml/badge.svg)](https://github.com/loquemedalagana/ipsec-gateway-lab/actions/workflows/cilium.yml)

리눅스 네트워크 네임스페이스만으로 만든 작은 VPN 게이트웨이 실습입니다.
클라이언트와 게이트웨이 사이를 IPsec(ESP 터널 모드)으로 암호화하고, 게이트웨이에서 기본 거부 + 명시 허용으로 접근을 제어한 뒤, 패킷 캡처와 연결 매트릭스로 확인합니다.

별도 VPN 소프트웨어 없이 리눅스 커널 기능(`ip netns`, `ip xfrm`, `nftables`)만으로 구성했고, 셸 스크립트로 조립했습니다.

같은 질문을 쿠버네티스의 노드 간 투명 암호화(Cilium IPsec)에 던진 비교 단계가 따로 있습니다 → [비교: 쿠버네티스 노드 간 투명 암호화](#비교-쿠버네티스-노드-간-투명-암호화-cilium-ipsec)

## 확인하려는 것

1. 터널을 지나는 요청은 외부망에서 ESP로만 보이고, 터널 안 주소·포트·내용은 보이지 않는가
2. 암호화와 접근제어는 별개인가 — 터널로 들어왔더라도 허용 목록에 없는 목적지는 차단되는가
3. IPsec이 적용되지 않은 요청은 차단되는가
4. 차단은 이유와 함께 기록되는가
5. SA가 없어졌을 때 요청이 평문으로 유출되지 않는가

## 구성

```mermaid
flowchart LR
  subgraph C["client (사용자 단말)"]
    c1["바깥 주소 10.0.1.2<br/>터널 안 주소 10.9.0.2"]
  end
  subgraph N["net (외부망)"]
    br["br0 브리지<br/>캡처 지점 1"]
  end
  subgraph G["gw (게이트웨이)"]
    g1["10.0.1.1<br/>IPsec 종단 + nftables"]
  end
  subgraph A["app"]
    a1["10.0.2.10:8080<br/>허용 대상"]
  end
  subgraph D["db"]
    d1["10.0.3.20:5432<br/>차단 대상"]
  end
  c1 == "ESP 터널 (암호문)" ==> br
  br == "ESP 터널 (암호문)" ==> g1
  g1 -- "허용 1건, 평문 (캡처 지점 2)" --> a1
  g1 -. "기본 거부" .-> d1
  classDef client fill:#1D4ED8,stroke:#1E3A8A,stroke-width:2px,color:#FFFFFF
  classDef wan fill:#6D28D9,stroke:#4C1D95,stroke-width:2px,color:#FFFFFF
  classDef gw fill:#D97706,stroke:#92400E,stroke-width:2px,color:#FFFFFF
  classDef allow fill:#15803D,stroke:#14532D,stroke-width:2px,color:#FFFFFF
  classDef deny fill:#B91C1C,stroke:#7F1D1D,stroke-width:2px,color:#FFFFFF
  class c1 client
  class br wan
  class g1 gw
  class a1 allow
  class d1 deny
  linkStyle 0,1 stroke:#1D4ED8,stroke-width:4px
  linkStyle 2 stroke:#15803D,stroke-width:3px
  linkStyle 3 stroke:#B91C1C,stroke-width:3px
```

| 네임스페이스 | 역할 |
|---|---|
| `client` | 사용자 단말. 터널 안 주소 `10.9.0.2`로 내부망에 접근 |
| `net` | 클라이언트와 게이트웨이 사이의 외부망(브리지). 제3자가 보는 패킷을 여기서 캡처 |
| `gw` | 게이트웨이. IPsec 종단 + nftables 접근제어 |
| `app`, `db` | 내부 서버. 둘 다 실제로 포트를 열고 있음 |

- IPsec: ESP 터널 모드, AES-GCM, 방향별 SA 2개. 키는 실행할 때마다 새로 만들고 출력하지 않습니다 → [lab/setup.sh](lab/setup.sh)
- 접근제어: forward 체인 기본 거부, 허용 1건(`터널 사용자 → app:8080`), 차단은 이유별 카운터 → [lab/policy.nft](lab/policy.nft)

## 이론과 명령의 대응

정보보안기사를 준비하며 이론으로 배운 IPsec·접근통제 개념이 리눅스에서 어떤 명령과 패킷으로 나타나는지 확인하려고 만들었습니다.

| 이론 | 이 실습에서 | 확인하는 곳 |
|---|---|---|
| ESP: 기밀성과 무결성을 제공하는 IPsec 프로토콜 | `proto esp` | 외부망 캡처의 `ESP(spi=…)` |
| 터널 모드: 원래 IP 패킷 전체를 암호화하고 새 IP 헤더를 붙임 | `mode tunnel` | 외부망에는 바깥 주소 `10.0.1.2 > 10.0.1.1`만, 안쪽 주소 `10.9.0.2`는 안 보임 |
| SA(보안 연관): 단방향이고 SPI로 식별 | `ip xfrm state` 2개 (`spi 0x1001`, `0x1002`) | 방향마다 다른 SPI가 캡처에 기록됨 |
| 보안 정책(SPD): 어떤 트래픽에 IPsec을 적용할지 | `ip xfrm policy` | 터널 안 주소로 보낸 요청만 ESP로 나감 |
| 재전송 방지: 순서 번호와 윈도우 | `replay-window 32` | 캡처의 `seq=0x1, 0x2, …` |
| 인증 암호화(AEAD) | `aead rfc4106(gcm(aes))` | SA 출력 |
| ARP: IP 주소로 MAC 주소를 알아냄 | 설정 없음 (커널이 첫 패킷 전에 자동 수행) | 두 캡처 맨 앞의 `ARP, Request who-has …`. IPsec은 IP 계층부터 보호하므로 ARP는 터널 밖에서 평문으로 보임 |
| 키 교환(IKE) | 없음 — 키를 스크립트가 직접 넣음 | 「한계」 참조 |
| 기본 거부 + 명시 허용 | nftables `policy drop` + 허용 1줄 | 연결 매트릭스, 카운터 |

## 실행

GitHub Actions가 푸시마다 전체를 실행합니다. 실행 화면의 **Summary**에 연결 매트릭스, 카운터, 패킷 캡처가 표시되고, 원본은 `evidence` 아티팩트로 남습니다.

로컬(리눅스, root):

```bash
sudo ./run.sh
```

macOS에서는 Docker로 실행합니다.

```bash
docker run --rm --privileged -v "$PWD":/lab ubuntu:24.04 bash -c 'apt-get update -qq && apt-get install -y -qq iproute2 nftables tcpdump curl python3 && /lab/run.sh'
```

## 검사 항목

[run.sh](run.sh)는 아래가 하나라도 어긋나면 실패로 끝납니다.

| 검사 | 기대 |
|---|---|
| 외부망 캡처 | ESP 패킷이 있고, 터널 안 주소(`10.9.0.2`)와 포트(`8080`)는 0건 |
| 터널 안쪽 캡처 | 복호화된 HTTP 요청이 보임 |
| 터널 → app:8080 | ALLOW |
| 터널 → app:22 | DROP (허용 외 포트) |
| 터널 → db:5432 | DROP (허용 외 서버, 포트는 열려 있음) |
| 터널 없이 → app:8080 | DROP |
| 카운터 | `allow_app`, `deny_no_tunnel`, `deny_not_allowed` 모두 0보다 큼 |
| 장애 실험 (a)(b) | 요청 실패, 외부망 평문 0건, app 도착 0건 |

결과는 세 가지로 나눕니다. `ALLOW`는 응답을 받은 것, `DROP`은 시간 초과(패킷이 응답 없이 폐기됨), `REFUSED`는 연결 거부(서버까지 갔는데 포트가 닫혀 있음)입니다. 정책이 차단했다면 `DROP`이어야 하고, `REFUSED`가 나오면 정책이 아니라 닫힌 포트 때문에 실패한 것이므로 검사가 실패합니다.

허용해야 할 쌍만 보면 "전부 열려 있는" 상태도 통과하고, 차단해야 할 쌍만 보면 "전부 차단된" 상태도 통과합니다. 그래서 둘 다 검사합니다.

## 장애 실험: SA가 없어지면 평문으로 유출되는가

VPN에서 가장 피해야 할 실패는 "터널이 동작하지 않는데 요청이 평문으로 그대로 전송되는 것"입니다. 보안 정책(SP)은 그대로 두고 SA만 지워서 확인했습니다.

```mermaid
sequenceDiagram
  participant C as client
  participant N as net (br0)
  participant G as gw
  participant A as app
  rect rgba(217, 119, 6, 0.45)
    Note over C,A: (a) 게이트웨이의 SA만 삭제
    C->>N: ESP
    N->>G: ESP
    Note over G: 복호화할 SA가 없어 폐기 (XfrmInNoStates)
    Note over A: 도착 0건
  end
  rect rgba(185, 28, 28, 0.42)
    Note over C,A: (b) 클라이언트의 SA도 삭제
    Note over C: 정책은 있지만 쓸 SA가 없어 내보내지 않음 (XfrmOutNoStates)
    Note over N: 지나가는 패킷 0개
  end
```

| 상황 | 요청 결과 | 외부망 ESP | 외부망 평문 | app 도착 | 커널 통계 |
|---|---|---|---|---|---|
| (a) 게이트웨이의 SA 삭제 | DROP | 2 | 0 | 0 | gw `XfrmInNoStates=2` |
| (b) 클라이언트의 SA도 삭제 | DROP | 0 | 0 | 0 | client `XfrmOutNoStates=6` |

(로컬 Docker와 GitHub Actions에서 같은 값. 패킷 수는 재전송 횟수에 따라 달라질 수 있고, 검사는 "요청 실패, 평문 0건, app 도착 0건"만 봅니다.)

- (a) 클라이언트는 계속 암호화해 보냈지만(ESP 2개) 게이트웨이에 복호화할 SA가 없어 폐기했습니다. 암호문은 내부로 전달되지 않았습니다.
- (b) 클라이언트는 "이 목적지는 ESP로 보내라"는 정책은 있는데 쓸 SA가 없어서, 패킷을 전송하지 않았습니다. 외부망에는 아무것도 지나가지 않았습니다.
- 두 경우 모두 실패 시 차단(fail-closed)으로 동작했습니다. 대신 요청은 2초 시간 초과로 끝나고, 사용자에게는 이유가 보이지 않습니다. 원인은 커널 통계(`/proc/net/xfrm_stat`)에만 남습니다. 운영한다면 이 값을 모니터링해야 합니다.
- 순서는 (a) 다음 (b)입니다. (b)는 게이트웨이 SA도 없는 상태에서 실행했습니다.

## 만들면서 잘못 판단했던 것

**닫힌 포트로는 정책을 검사할 수 없다.**
`터널 → app:22`가 차단되는지 검사했는데, app은 22번 포트를 열고 있지 않았습니다. 정책이 전혀 없어도 "실패"로 나오는 검사였습니다. 처음 검사는 성공과 실패만 구분해서 이 차이를 볼 수 없었습니다. 결과를 `DROP`(시간 초과)과 `REFUSED`(연결 거부)로 나누고, 정책이 차단한 경우에만 통과하도록 바꿨습니다.

**수신 측 인터페이스에서 캡처하면 평문이 보인다.**
처음에는 게이트웨이의 외부 쪽 인터페이스(`gw-wan`)에서 캡처했습니다. ESP 패킷 바로 다음 줄에 `10.9.0.2 > 10.0.2.10.8080` 평문 SYN이 기록돼서, "평문 노출 0건" 검사가 실패했습니다.

암호화가 안 된 것이 아니었습니다. 리눅스는 ESP를 복호화한 뒤 안쪽 패킷을 같은 인터페이스로 다시 받은 것처럼 처리하기 때문에, 수신 측에서 캡처하면 암호문과 복호화된 패킷이 둘 다 보입니다. 전송 구간의 패킷을 보려면 양 끝이 아닌 중간 지점에서 캡처해야 합니다. 그래서 둘 사이에 `net` 네임스페이스(브리지)를 넣고 거기서 캡처하도록 바꿨습니다.

## 비교: 쿠버네티스 노드 간 투명 암호화 (Cilium IPsec)

위 실습은 사용자 단말과 게이트웨이 사이에 SA와 키를 직접 넣는 **게이트웨이형**입니다. 같은 커널 기능(xfrm, ESP)을 쿠버네티스에서는 Cilium이 **노드와 노드 사이**에 겁니다. 파드는 암호화를 모르고, 설정은 Secret 하나와 설치 옵션 두 개입니다. 같은 질문을 던졌을 때 무엇이 같고 무엇이 다른지 실측했습니다.

kind로 노드 2개짜리 클러스터를 만들고 Cilium을 IPsec을 켠 채로 설치한 뒤, 파드 4개와 정책 1개를 올립니다 → [cilium/](cilium/), [run-cilium.sh](run-cilium.sh)

```mermaid
flowchart LR
  subgraph CPN["control-plane 노드"]
    cr["client-remote<br/>role=client"]
    ot["other<br/>role=other"]
    e1["eth0<br/>캡처 지점 1 (egress 방향)"]
  end
  subgraph WKN["worker 노드"]
    e2["eth0<br/>IPsec 복호화"]
    cl["client-local<br/>role=client"]
    ap["app<br/>:8080 허용, :9090 차단<br/>캡처 지점 2 (노드 내부)"]
  end
  cr -- "평문" --> e1
  e1 == "ESP (암호문)" ==> e2
  e2 -- "평문" --> ap
  cl -- "평문, eth0을 지나지 않음" --> ap
  ot -. "정책 차단 (worker에서 폐기)" .-> ap
  classDef client fill:#1D4ED8,stroke:#1E3A8A,stroke-width:2px,color:#FFFFFF
  classDef wan fill:#6D28D9,stroke:#4C1D95,stroke-width:2px,color:#FFFFFF
  classDef allow fill:#15803D,stroke:#14532D,stroke-width:2px,color:#FFFFFF
  classDef deny fill:#B91C1C,stroke:#7F1D1D,stroke-width:2px,color:#FFFFFF
  class cr,cl client
  class e1,e2 wan
  class ap allow
  class ot deny
  linkStyle 1 stroke:#1D4ED8,stroke-width:4px
  linkStyle 2,3 stroke:#15803D,stroke-width:3px
  linkStyle 4 stroke:#B91C1C,stroke-width:3px
```

### 검사 항목

[cilium/check.sh](cilium/check.sh)는 아래가 하나라도 어긋나면 실패로 끝납니다. 출력 형식과 `ALLOW`/`DROP`/`REFUSED`의 뜻은 `run.sh`와 같습니다.

| 검사 | 기대 |
|---|---|
| 암호화 상태 | Cilium 에이전트가 `Encryption: IPsec`이라고 답함 |
| 다른 노드의 파드 사이 (client-remote → app) | 송신 노드의 `eth0`에 ESP가 있고, 파드 주소·포트 `8080`·요청 경로의 마커 문자열은 0건. 수신 노드 내부에서는 마커 문자열이 보임 |
| 같은 노드의 파드 사이 (client-local → app) | 노드 내부에서 마커 문자열이 평문으로 보이고, `eth0`에는 이 요청이 0건 |
| client(다른 노드) → app:8080 | ALLOW |
| client(같은 노드) → app:8080 | ALLOW |
| client → app:9090 | DROP (허용 외 포트, 포트는 열려 있음) |
| other → app:8080 | DROP (허용 외 파드) |
| 차단 기록 | worker 노드의 `Policy denied` 폐기 수가 매트릭스 전보다 늘어남 |
| 결과 파일 | 키처럼 보이는 긴 16진수가 없음 |

노드 사이에는 이 요청과 무관한 통신도 ESP로 오갑니다. ESP 개수만으로는 "내 요청이 암호화됐다"고 말할 수 없어서, 요청 경로에 실행할 때마다 다른 문자열(`/cross-…`, `/same-…`)을 넣고 그 문자열이 어디에서 평문으로 보이는지를 기준으로 삼았습니다.

### 결과

로컬(macOS, Docker Desktop, kind v0.33.0, Cilium 1.20.1)에서 클러스터를 지우고 처음부터 실행한 값입니다.

| 요청 | 노드 간 구간(`eth0`) ESP | 노드 간 구간 평문 노출 | 노드 내부에서 보인 평문 요청 |
|---|---|---|---|
| 다른 노드 (client-remote → app) | 6 | 0 | 4 |
| 같은 노드 (client-local → app) | 0 | 0 | 4 |

| 경로 | 기대 | 결과 |
|---|---|---|
| client(다른 노드) → app:8080 | ALLOW | ALLOW |
| client(같은 노드) → app:8080 | ALLOW | ALLOW |
| client → app:9090 (허용 외 포트) | DROP | DROP |
| other → app:8080 (허용 외 파드) | DROP | DROP |

- 다른 노드로 간 요청은 노드 간 구간에서 `172.18.0.2 > 172.18.0.3: ESP(spi=0x00000003,…)`으로만 보였습니다. 바깥 주소는 노드 주소이고 파드 주소는 보이지 않습니다. 같은 요청이 수신 노드 내부에서는 `10.244.0.123 > 10.244.1.94.8080`, `GET /cross-… HTTP/1.1`로 보였습니다.
- 같은 노드 안의 요청은 파드의 veth(`lxc…`)에서 `GET /same-… HTTP/1.1`이 평문으로 보였고, `eth0`에는 나가지 않았습니다. **암호화는 노드를 벗어나는 구간에만 적용됩니다.**
- 정책에 없는 요청 2건은 모두 `DROP`이었고, worker 노드의 `cilium_drop_count_total{direction=INGRESS, reason=Policy denied}`가 0에서 4로 늘었습니다.
- worker 노드의 SA는 4개였고 모두 `proto esp spi 0x00000003 mode tunnel`, `aead rfc4106(gcm(aes))`입니다. SA의 주소 쌍은 노드 IP 쌍과 파드 대역(`10.244.x.x`) 안의 주소 쌍 두 종류였고, 실습 파드의 주소를 가진 SA는 없었습니다. 파드마다 SA가 생기지는 않습니다.

(패킷 수와 주소는 실행마다 달라질 수 있고, 검사는 위 「검사 항목」의 조건만 봅니다.)

### 네거티브 테스트: 의도적으로 잘못 구성했을 때

검사가 "항상 통과하는 검사"가 아닌지 확인하려고 두 가지 방식으로 의도적으로 잘못 구성해 봤습니다. 둘 다 `RESULT: FAIL`, 종료 코드 1로 끝났습니다.

| 바꾼 것 | 암호화 검사 | 연결 매트릭스 | 차단 기록 |
|---|---|---|---|
| IPsec을 끄고 설치 (`ENCRYPT=0 ./run-cilium.sh`) | 실패: 상태 `Disabled`, 노드 간 구간 ESP 0개, 평문 노출 7건 | 4건 모두 기대와 일치 | 0 → 4 |
| 정책 삭제 (`kubectl delete -f cilium/policy.yaml` 뒤 `cilium/check.sh`) | 통과 | 실패: `app:9090`, `other → app:8080`이 `ALLOW` | 실패: 8 → 8 (늘지 않음) |

암호화를 꺼도 정책은 그대로 차단했고, 정책을 지워도 암호화는 그대로였습니다. 게이트웨이형에서 확인한 "암호화와 접근제어는 별개"가 여기서도 같습니다.

### 게이트웨이형과 나란히

| | 게이트웨이형 (`run.sh`) | 노드 간 투명 암호화 (`run-cilium.sh`) |
|---|---|---|
| 암호화 구간 | 사용자 단말 ↔ 게이트웨이 | 노드 ↔ 노드 |
| 누가 암호화를 아는가 | 단말에 SA·정책·터널 안 주소가 있어야 함 | 파드는 모름. 노드의 커널이 처리 |
| SA의 주소 | 단말과 게이트웨이의 바깥 주소 | 노드마다 정해진 주소 쌍. 파드별 SA 없음 |
| SA·키를 넣는 주체 | 스크립트가 `ip xfrm`으로 직접. 방향별 키 2개 | Secret 하나를 주면 Cilium 에이전트가 각 노드에 SA를 설치 |
| SPI | 방향마다 다름 (`0x1001`, `0x1002`) | 양방향 모두 `0x00000003` (Secret의 키 번호) |
| 암호화 대상을 정하는 것 | 보안 정책(SP): `10.9.0.2 ↔ 10.0.2.0/23` | 목적지 파드가 다른 노드에 있는지 |
| 바깥 구간 캡처 | ESP만, 터널 안 주소·포트 0건 | ESP만, 파드 주소·포트·요청 내용 0건 |
| 암호화되지 않는 경로 | IPsec이 적용되지 않은 요청은 게이트웨이가 차단 (`DROP`) | 같은 노드의 파드 사이는 평문으로 전달 (`ALLOW`) |
| 접근제어를 하는 곳 | 게이트웨이 한 곳 (nftables forward 체인) | 받는 파드가 있는 노드 (Cilium 정책) |
| 요청자를 구분하는 기준 | 터널 안 주소 `10.9.0.2` | 파드 라벨 `role=client` |
| 차단 기록 | nftables 카운터 (`deny_no_tunnel`, `deny_not_allowed`) | Cilium 통계 (`Policy denied`) |
| SA가 없어졌을 때 | 실험함: 실패 시 차단 | 실험하지 않음 |
| 실행 | 리눅스 네임스페이스, root | kind 클러스터, Docker |

가장 큰 차이는 "암호화되지 않는 경로"입니다. 게이트웨이형은 터널을 거치지 않으면 내부로 들어올 수 없게 만드는 것이 목적이라, IPsec이 적용되지 않은 요청을 차단합니다. 노드 간 투명 암호화는 노드 밖 구간의 도청을 막는 것이 목적이라, 같은 노드 안의 요청은 평문인 채로 허용합니다. 누가 무엇에 접근할 수 있는지는 두 경우 모두 암호화가 아니라 별도의 정책이 정합니다.

### 실행

`docker`, `kind`, `kubectl`, `cilium`(cilium-cli)이 필요합니다. root 권한은 필요 없습니다.

```bash
./run-cilium.sh
```

- 올리기 전에 Docker에 남은 메모리를 확인하고, 3000MiB보다 적으면 클러스터를 만들지 않고 끝냅니다(`NEED_MB`로 조정).
- 전용 kubeconfig 파일을 쓰므로 `~/.kube/config`와 현재 컨텍스트는 바뀌지 않습니다. 끝나면 클러스터 `ipsec-compare`를 지웁니다.
- `KEEP=1 ./run-cilium.sh`는 클러스터를 남깁니다. `cilium/check.sh`만 다시 돌릴 수 있고, 정리는 `cilium/down.sh`입니다.
- IPsec 키는 실행할 때마다 새로 만들어 표준 입력으로 Secret에 넣습니다. 화면과 파일에 출력하지 않습니다 → [cilium/up.sh](cilium/up.sh)
- 결과는 `out-cilium/`에 남습니다.

### 이 비교의 한계

- 캡처 지점이 경로 중간(제3자 관점)이 아닙니다. 게이트웨이형에서는 양 끝 사이의 브리지에서 캡처했지만, 여기서는 송신 노드의 `eth0`에서 egress(송신) 방향만 캡처했습니다. 노드 사이의 Docker 브리지에서는 캡처하지 않았습니다.
- "같은 노드의 요청은 암호화되지 않는다"는 노드 내부에서 평문이 보이고 `eth0`에 나가지 않았다는 것으로 확인했습니다. 노드 안에서 패킷이 지나는 모든 지점을 본 것은 아닙니다.
- SA를 지웠을 때 평문으로 유출되는지(게이트웨이형의 장애 실험)는 Cilium 쪽에서 실험하지 않았습니다.
- 키 교체는 실험하지 않았습니다. 키는 설치할 때 한 번 넣습니다.
- 노드 2개, 파드 4개, 정책 1개입니다. 서비스(ClusterIP)를 거치는 요청, 클러스터 밖으로 나가는 요청, 호스트 네트워크 파드는 다루지 않았습니다.
- 지연과 처리량은 측정하지 않았습니다.
- 이 단계는 [별도 워크플로](.github/workflows/cilium.yml)로 두었고, GitHub Actions(ubuntu-24.04)에서도 같은 검사가 통과했습니다. 위 수치는 로컬 실행 결과입니다.

## 한계

- SA와 키를 스크립트가 직접 넣습니다. 키 교환(IKE), 키 교체, 사용자 인증이 없습니다. 사용자는 터널 안 주소 하나로만 식별됩니다.
- 한 호스트 안의 네임스페이스입니다. 실제 NAT, MTU·단편화, 패킷 손실은 다루지 않습니다.
- 게이트웨이는 한 대입니다. 이중화와 장애 전환은 없습니다.
- 차단 기록은 카운터까지입니다. 어떤 연결이 차단됐는지 건별 로그는 남기지 않습니다.
- ARP는 암호화 대상이 아니어서 외부망에 그대로 보입니다. 외부망에서 ARP 스푸핑을 했을 때 어떻게 되는지는 실험하지 않았습니다.
- 지연은 측정하지 않았습니다.

## AI 도구 사용

스크립트와 문서 초안은 AI 도구(Claude Code)로 작성했습니다. 구성 범위와 검사 항목은 직접 정했고, 실행 결과는 직접 확인했습니다.
