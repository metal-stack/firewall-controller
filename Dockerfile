FROM scratch
WORKDIR /
COPY bin/firewall-controller .
RUN apt update \
 && apt install -y --no-install-recommends nftables
ENTRYPOINT ["/firewall-controller"]
