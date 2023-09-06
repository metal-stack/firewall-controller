FROM alpine:3.18
COPY bin/firewall-controller-webhook .
USER 65534
ENTRYPOINT ["/firewall-controller-webhook"]
