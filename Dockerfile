FROM debian:10
WORKDIR /
COPY bin/firewall-controller .
RUN apt update \
 && apt install -y --no-install-recommends nftables
ENTRYPOINT ["/firewall-controller"]
