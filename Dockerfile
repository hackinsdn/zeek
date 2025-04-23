FROM zeek/zeek:latest

RUN set -x \
 && export DEBIAN_FRONTEND=noninteractive \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
		iproute2 net-tools iputils-ping \
		socat procps curl jq \
                python3-minimal libpython3-stdlib \
		g++ cmake make libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

COPY files/ /

ENTRYPOINT ["/docker-entrypoint.sh"]
