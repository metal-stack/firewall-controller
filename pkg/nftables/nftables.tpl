table ip firewall {
	# local prefixes set
	set local_prefixes {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { {{ .LocalPrefixes }} }
	}

	chain forward {
		type filter hook forward priority 1; policy drop;

		# network traffic accounting
		ip saddr != @local_prefixes counter comment "in_bytes"
		ip daddr != @local_prefixes counter comment "out_bytes"

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

		counter comment "count dropped packets"
		limit rate 10/second counter packets 1 bytes 40 log prefix "nftables-firewall-dropped: "
	}
}
