# Firewall Controller

This controller is installed on a bare-metal firewall in front of several kubernetes worker nodes and responsible to reconcile a `ClusterwideNetworkPolicy` to nftables rules to control access to and from the kubernetes cluster.
It allows also to control the traffic rate going through, to limit network resources for restricted usage scenarios. Nftable and node metrics are exposed with the `nftables-exporter` and `node-exporter`, the ips are visible as service and endpoint from the kubernetes cluster.

Additional an IDS is managed on the firewall to detect known network anomalies. [suricata](https://suricata-ids.org) is used for this purpose. Right now, only basic statistics about the amount of scanned packets is reported. In a future release, access to all alarms will be provided.

## Architecture

![Architecture](architecture.svg)

## Configuration

Firewall Controller is configured with 2 CRDs: `firewalls.metal-stack.io` and `clusterwidenetworkpolicies.metal-stack.io`. Both are namespaced and must reside in the `firewall` namespace.
The `firewalls` CRD is typically written from the gardener-extensio-provider-metal, the `clusterwidenetworkpolicy` should be provided by the deployment of your application.

Example Firewall CRD:

```yaml
apiVersion: metal-stack.io/v1
kind: Firewall
metadata:
  namespace: firewall
  name: firewall
spec:
  # Interval of reconcilation if nftables rules and network traffic accounting
  interval: 10s
  # Ratelimits specify on which physical interface, which maximum rate of traffic is allowed
  ratelimits:
  # The name of the interface visible with ip link show
  - interface: vrf104009
    # The maximum rate in MBits/s
    rate: 10
  # Internalprefixes defines a list of prefixes where the traffic going to, or comming from is considered internal, e.g. not leaving into external networks
  # given the archictecture picture above this would be:
  internalprefixes:
  - "1.2.3.0/24
  - "172.17.0.0/16"
  - "10.0.0.0/8"
```

Example ClusterwideNetworkPolicy:

```yaml
apiVersion: metal-stack.io/v1
kind: ClusterwideNetworkPolicy
metadata:
  namespace: firewall
  name: clusterwidenetworkpolicy-sample
spec:
  egress:
  - to:
    - cidr: 1.1.0.0/24
      except:
      - 1.1.1.0/16
    - cidr: 8.8.8.8/32
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

## Status

Once the firewall-controller is running, it will report several statistics to the Firewall CRD Status:
This can be inspected by running:

```bash
kubectl describe -n firewall firewall
```

The output would look like:

```yaml
Status:
  Last Run:  2020-06-17T13:18:58Z
  Stats:
    # Network traffic in bytes separated into external and internal in/out/total
    Devices:
      External:
        In:     91696
        Out:    34600
        Total:  0
      Internal:
        In:     0
        Out:    0
        Total:  2678671
    # IDS Statistics by interface
    Idsstats:
      vrf104009:
        Drop:              1992
        Invalidchecksums:  0
        Packets:           4997276
    # nftable rule statistics by rule name
    Rules:
      Accept:
        BGP unnumbered:
          Counter:
            Bytes:    0
            Packets:  0
        SSH incoming connections:
          Counter:
            Bytes:    936
            Packets:  16
        accept established connections:
          Counter:
            Bytes:    21211168
            Packets:  39785
        accept icmp:
          Counter:
            Bytes:    0
            Packets:  0
        accept traffic for k8s service kube-system/vpn-shoot:
          Counter:
            Bytes:    360
            Packets:  6
      Drop:
        drop invalid packets:
          Counter:
            Bytes:    52
            Packets:  1
        drop invalid packets from forwarding to prevent malicious activity:
          Counter:
            Bytes:    0
            Packets:  0
        drop invalid packets to prevent malicious activity:
          Counter:
            Bytes:    0
            Packets:  0
        drop packets with invalid ct state:
          Counter:
            Bytes:    0
            Packets:  0
        drop ping floods:
          Counter:
            Bytes:    0
            Packets:  0
      Other:
        block bgp forward to machines:
          Counter:
            Bytes:    0
            Packets:  0
        count and log dropped packets:
          Counter:
            Bytes:    2528
            Packets:  51
        snat (networkid: internet):
          Counter:
            Bytes:    36960
            Packets:  486
```

It is also possible to tail for the dropped packets with the following command (install stern from https://github.com/wercker/stern):

```bash
stern -n firewall drop
```

The output will look like:

```json

droptailer-6d556bd988-4g8gp droptailer 2020-06-17 13:23:27 +0000 UTC {"DPT":"4000","DST":"1.2.3.4","ID":"54321","IN":"vrf104009","LEN":"40","MAC":"ca:41:f9:80:fa:89:aa:bb:0e:62:8c:a6:08:00","OUT":"vlan179","PREC":"0x00","PROTO":"TCP","RES":"0x00","SPT":"38464","SRC":"2.3.4.5","SYN":"","TOS":"0x00","TTL":"236","URGP":"0","WINDOW":"65535","timestamp":"2020-06-17 13:23:27 +0000 UTC"}
droptailer-6d556bd988-4g8gp droptailer 2020-06-17 13:23:34 +0000 UTC {"DPT":"2362","DST":"1.2.3.4","ID":"44545","IN":"vrf104009","LEN":"40","MAC":"ca:41:f9:80:fa:89:aa:bb:0e:62:8c:a6:08:00","OUT":"","PREC":"0x00","PROTO":"TCP","RES":"0x00","SPT":"40194","SRC":"2.3.4.5","SYN":"","TOS":"0x00","TTL":"242","URGP":"0","WINDOW":"1024","timestamp":"2020-06-17 13:23:34 +0000 UTC"}
droptailer-6d556bd988-4g8gp droptailer 2020-06-17 13:23:30 +0000 UTC {"DPT":"650","DST":"1.2.3.4","ID":"12399","IN":"vrf104009","LEN":"40","MAC":"ca:41:f9:80:fa:89:aa:bb:0e:62:8c:a6:08:00","OUT":"vlan179","PREC":"0x00","PROTO":"TCP","RES":"0x00","SPT":"40194","SRC":"2.3.4.5","SYN":"","TOS":"0x00","TTL":"241","URGP":"0","WINDOW":"1024","timestamp":"2020-06-17 13:23:30 +0000 UTC"}
droptailer-6d556bd988-4g8gp droptailer 2020-06-17 13:23:34 +0000 UTC {"DPT":"2362","DST":"1.2.3.4","ID":"44545","IN":"vrf104009","LEN":"40","MAC":"ca:41:f9:80:fa:89:aa:bb:0e:62:8c:a6:08:00","OUT":"","PREC":"0x00","PROTO":"TCP","RES":"0x00","SPT":"40194","SRC":"2.3.4.5","SYN":"","TOS":"0x00","TTL":"242","URGP":"0","WINDOW":"1024","timestamp":"2020-06-17 13:23:34 +0000 UTC"}
droptailer-6d556bd988-4g8gp droptailer 2020-06-17 13:23:10 +0000 UTC {"DPT":"63351","DST":"1.2.3.4","ID":"11855","IN":"vrf104009","LEN":"40","MAC":"ca:41:f9:80:fa:89:aa:bb:0e:62:8c:a6:08:00","OUT":"vlan179","PREC":"0x00","PROTO":"TCP","RES":"0x00","SPT":"54589","SRC":"2.3.4.5","SYN":"","TOS":"0x00","TTL":"245","URGP":"0","WINDOW":"1024","timestamp":"2020-06-17 13:23:10 +0000 UTC"}
droptailer-6d556bd988-4g8gp droptailer 2020-06-17 13:23:51 +0000 UTC {"DPT":"8002","DST":"1.2.3.4","ID":"17539","IN":"vrf104009","LEN":"40","MAC":"ca:41:f9:80:fa:89:aa:bb:0e:62:8c:a6:08:00","OUT":"","PREC":"0x00","PROTO":"TCP","RES":"0x00","SPT":"47615","SRC":"2.3.4.5","SYN":"","TOS":"0x08","TTL":"239","URGP":"0","WINDOW":"1024","timestamp":"2020-06-17 13:23:51 +0000 UTC"}
```

You can forward the droptailer logs to any log aggregation infrastructure you have in place.
