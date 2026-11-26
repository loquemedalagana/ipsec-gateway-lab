# 로컬에서 run.sh 를 돌려 보기 위한 개발 이미지. GitHub Actions(ubuntu-24.04)와 같은 패키지를 담는다.
# 빌드:  docker build -t ipsec-lab-dev .
# 실행:  docker run --rm --privileged -v "$PWD":/lab -w /lab ipsec-lab-dev ./run.sh
FROM ubuntu:24.04
# --no-install-recommends 는 쓰지 않는다: strongSwan 의 openssl 플러그인이 추천 패키지로 딸려 오고,
# 빼면 데몬이 뜨지 않는다. GitHub Actions 의 설치 스텝과 같은 패키지 목록을 쓴다.
RUN apt-get update -qq && apt-get install -y -qq \
      iproute2 nftables tcpdump curl python3 \
      strongswan-charon strongswan-swanctl dsniff \
    && rm -rf /var/lib/apt/lists/*
