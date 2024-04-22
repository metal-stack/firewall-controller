table inet firewall {
    # internal prefixes, which are not leaving the partition or the partition interconnect
    set internal_prefixes {
        type ipv4_addr
        flags interval
        auto-merge
        {{- if gt (len .InternalPrefixes) 0 }}
        elements = { {{ .InternalPrefixes }} }
        {{- end }}
    }

    # Prefixes in the cluster, typically 10.x.x.x
    # FIXME Should be filled with nodeCidr
    set cluster_prefixes {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8 }
    }
    {{- range .Sets }}

    set {{ .SetName }} {
        type {{ .Version }}
        {{- if gt (len .IPs) 0 }}
        elements = { {{ StringsJoin .IPs ", " }} }
        {{- end }}
    }
    {{- end }}

    # counters
    counter internal_in { }
    counter internal_out { }
    counter external_in { }
    counter external_out { }
    counter drop_total { }
    counter drop_ratelimit { }

    chain forward {
        type filter hook forward priority 1; policy drop;

        # network traffic accounting for external traffic
        ip saddr != @internal_prefixes oifname {"vlan{{ .PrivateVrfID }}", "vrf{{ .PrivateVrfID }}"} counter name external_in comment "count external traffic incomming"
        ip daddr != @internal_prefixes iifname {"vlan{{ .PrivateVrfID }}", "vrf{{ .PrivateVrfID }}"} counter name external_out comment "count external traffic outgoing"

        # network traffic accounting for internal traffic
        ip saddr @internal_prefixes oifname {"vlan{{ .PrivateVrfID }}", "vrf{{ .PrivateVrfID }}"} counter name internal_in comment "count internal traffic incomming"
        ip daddr @internal_prefixes iifname {"vlan{{ .PrivateVrfID }}", "vrf{{ .PrivateVrfID }}"} counter name internal_out comment "count internal traffic outgoing"

        # rate limits
        {{- range .RateLimitRules }}
        {{ . }}
        {{- end }}

        # state dependent rules
        ct state established,related counter accept comment "accept established connections"
        ct state invalid counter drop comment "drop packets with invalid ct state"

        # icmp
        ip protocol icmp icmp type echo-request limit rate over 10/second burst 4 packets counter drop comment "drop ping floods"
        ip protocol icmp icmp type { destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem } counter log prefix "nftables-firewall-accepted: " accept comment "accept icmp"

        # dynamic ingress rules
        {{- range .ForwardingRules.Ingress }}
        {{ . }}
        {{- end }}

        # dynamic egress rules
        {{- range .ForwardingRules.Egress }}
        {{ . }}
        {{- end }}

        counter comment "count and log dropped packets"
        limit rate 10/second counter name drop_total log prefix "nftables-firewall-dropped: "
    }
}
{{- if and .DnsProxy .DnsProxy.Enabled }}
{{ $dnsProxy := .DnsProxy }}

table inet dnsproxy {
    # Prefixes in the cluster, typically 10.x.x.x
    # FIXME Should be filled with nodeCidr
    set cluster_prefixes {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8 }
    }

    set proxy_dns_servers {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { {{ StringsJoin $dnsProxy.DNSAddrs ", " }} }
    }

    chain prerouting {
        type nat hook prerouting priority 0; policy accept;
    {{- range $ip := $dnsProxy.ExternalIPs }}
    {{- range $iface := $dnsProxy.PrimaryIfaces }}
        ip daddr @proxy_dns_servers iifname "{{ $iface }}" tcp dport domain dnat ip to {{ $ip }} comment "dnat intercept traffic for dns proxy"
        ip daddr @proxy_dns_servers iifname "{{ $iface }}" udp dport domain dnat ip to {{ $ip }} comment "dnat intercept traffic for dns proxy"
    {{- end }}
    {{- end }}
    }

    chain prerouting_ct {
        type filter hook prerouting priority raw; policy accept;
    {{- range $iface := $dnsProxy.PrimaryIfaces }}
        iifname "{{ $iface }}" tcp dport domain ct zone set 3
        iifname "{{ $iface }}" udp dport domain ct zone set 3
    {{- end }}
    }

    chain input {
    {{- range $dnsProxy.ExternalIPs }}
        ip saddr @cluster_prefixes tcp dport domain ip daddr {{ . }} accept comment "dnat to dns proxy"
        ip saddr @cluster_prefixes udp dport domain ip daddr {{ . }} accept comment "dnat to dns proxy"
    {{- end }}
    }

    chain forward {
    {{- range $dnsProxy.DNSAddrs }}
        ip saddr == @cluster_prefixes ip daddr { {{ . }} } tcp dport { {{ $dnsProxy.DNSPort }} } counter accept comment "accept traffic for dns cache tcp"
        ip saddr == @cluster_prefixes ip daddr { {{ . }} } udp dport { {{ $dnsProxy.DNSPort }} } counter accept comment "accept traffic for dns cache udp"
    {{- end }}
    }

    chain output_ct {
        type nat hook output priority raw; policy accept;
    {{- range $iface := $dnsProxy.PrimaryIfaces }}
        iifname "{{ $iface }}" tcp dport domain ct zone set 3
        iifname "{{ $iface }}" udp dport domain ct zone set 3
    {{- end }}
    }

{{- if gt (len .SnatRules) 0 }}

    chain postrouting {
        type nat hook postrouting priority -1; policy accept;
        {{- range .SnatRules }}
        {{ . }}
        {{- end }}
    }
{{- end }}
}
{{- end }}
