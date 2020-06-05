table ip firewall {
	# internal prefixes, which are not leaving the partition or the partition interconnect
	set internal_prefixes {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { {{ .InternalPrefixes }} }
	}
	# Prefixes in the cluster, typically 10.x.x.x
	# FIXME Should be filled with nodeCidr
	set cluster_prefixes {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 10.0.0.0/8 }
	}

	# counters
	counter internal_total { }
	counter external_in { }
	counter external_out { }
	counter drop_total { }
	counter drop_ratelimit { }

	chain forward {
		type filter hook forward priority 1; policy drop;

		# network traffic accounting for external traffic
		ip saddr != @internal_prefixes ip saddr != @cluster_prefixes counter name external_in
		ip daddr != @internal_prefixes ip daddr != @cluster_prefixes counter name external_out

		# network traffic accounting for internal traffic
		ip daddr == @internal_prefixes ip saddr == @internal_prefixes counter name internal_total

		# rate limits
		{{- range .RateLimits }}
		meta iifname "{{ .Interface }}" limit rate over {{ .Rate }} mbytes/second counter name drop_ratelimit drop
		{{- end }}

		# state dependent rules
		ct state established,related counter accept comment "accept established connections"
		ct state invalid counter drop comment "drop packets with invalid ct state"

		# icmp
		ip protocol icmp icmp type echo-request limit rate over 10/second burst 4 packets counter drop comment "drop ping floods"
		ip protocol icmp icmp type { destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem } counter accept comment "accept icmp"

		# dynamic ingress rules
		{{- range .Ingress }}
		{{ . }}
		{{- end }}

		# dynamic egress rules
		{{- range .Egress }}
		{{ . }}
		{{- end }}

		counter comment "count and log dropped packets"
		limit rate 10/second counter name drop_total log prefix "nftables-firewall-dropped: "
	}
}
