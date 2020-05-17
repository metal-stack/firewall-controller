# local prefixes set
define local_prefixes = { {{ .LocalPrefixes }} }

table ip firewall {
	chain forward {
		type filter hook forward priority 1; policy drop;

		# state dependent rules
		ct state established,related counter accept comment "accept established connections"
		ct state invalid counter drop comment "drop packets with invalid ct state"

		# network traffic accounting
		ip saddr != $local_prefixes counter comment "count ingress ip traffic not from local prefixes"
		ip daddr != $local_prefixes counter comment "count egress ip traffic not to local prefixes"

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
