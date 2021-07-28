package nftables

import (
	"os"
	"testing"
)

func Test_equal(t *testing.T) {

	tests := []struct {
		name   string
		source string
		target string
		want   bool
	}{
		{
			name:   "two small files",
			source: "A\nB\nC\n",
			target: "C\nB\nA\n",
			want:   true,
		},
		{
			name: "two bigger files",
			source: `
table ip firewall {
	# internal prefixes, which are not leaving the partition or the partition interconnect
	set internal_prefixes {
		type ipv4_addr
		flags interval
		auto-merge
		
		elements = { 1.2.3.4 }
		
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
	counter internal_in { }
	counter internal_out { }
	counter external_in { }
	counter external_out { }
	counter drop_total { }
	counter drop_ratelimit { }

	chain forward {
		type filter hook forward priority 1; policy drop;

		# network traffic accounting for internal traffic
		ip saddr @internal_prefixes oifname {"vlan42", "vrf42"} counter name internal_in comment "count internal traffic incomming"
		ip daddr @internal_prefixes iifname {"vlan42", "vrf42"} counter name internal_out comment "count internal traffic outgoing"

		# network traffic accounting for external traffic
		ip saddr != @internal_prefixes oifname {"vlan42", "vrf42"} counter name external_in comment "count external traffic incomming"
		ip daddr != @internal_prefixes iifname {"vlan42", "vrf42"} counter name external_out comment "count external traffic outgoing"

		# rate limits
		meta iifname "eth0" limit rate over 10 mbytes/second counter name drop_ratelimit drop

		# state dependent rules
		ct state established,related counter accept comment "accept established connections"
		ct state invalid counter drop comment "drop packets with invalid ct state"

		# icmp
		ip protocol icmp icmp type echo-request limit rate over 10/second burst 4 packets counter drop comment "drop ping floods"
		ip protocol icmp icmp type { destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem } counter accept comment "accept icmp"

		# dynamic ingress rules
		ingress rule

		# dynamic egress rules
		egress rule

		counter comment "count and log dropped packets"
		limit rate 10/second counter name drop_total log prefix "nftables-firewall-dropped: "
	}
}
`,
			target: `
table ip firewall {
	# internal prefixes, which are not leaving the partition or the partition interconnect
	set internal_prefixes {
		type ipv4_addr
		flags interval
		auto-merge
		
		elements = { 1.2.3.4 }
		
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
	counter internal_in { }
	counter internal_out { }
	counter external_in { }
	counter external_out { }
	counter drop_total { }
	counter drop_ratelimit { }

	chain forward {
		type filter hook forward priority 1; policy drop;

		# network traffic accounting for external traffic
		ip saddr != @internal_prefixes oifname {"vlan42", "vrf42"} counter name external_in comment "count external traffic incomming"
		ip daddr != @internal_prefixes iifname {"vlan42", "vrf42"} counter name external_out comment "count external traffic outgoing"

		# network traffic accounting for internal traffic
		ip saddr @internal_prefixes oifname {"vlan42", "vrf42"} counter name internal_in comment "count internal traffic incomming"
		ip daddr @internal_prefixes iifname {"vlan42", "vrf42"} counter name internal_out comment "count internal traffic outgoing"

		# rate limits
		meta iifname "eth0" limit rate over 10 mbytes/second counter name drop_ratelimit drop

		# state dependent rules
		ct state established,related counter accept comment "accept established connections"
		ct state invalid counter drop comment "drop packets with invalid ct state"

		# icmp
		ip protocol icmp icmp type echo-request limit rate over 10/second burst 4 packets counter drop comment "drop ping floods"
		ip protocol icmp icmp type { destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem } counter accept comment "accept icmp"

		# dynamic ingress rules
		ingress rule

		# dynamic egress rules
		egress rule

		counter comment "count and log dropped packets"
		limit rate 10/second counter name drop_total log prefix "nftables-firewall-dropped: "
	}
}
`, want: true,
		},
	}
	for _, tt := range tests {
		s, err := os.CreateTemp("/tmp", "source")
		if err != nil {
			t.Fail()
		}
		dest, err := os.CreateTemp("/tmp", "target")
		if err != nil {
			t.Fail()
		}
		err = os.WriteFile(s.Name(), []byte(tt.source), 0600)
		if err != nil {
			t.Fail()
		}
		err = os.WriteFile(dest.Name(), []byte(tt.target), 0600)
		if err != nil {
			t.Fail()
		}

		t.Run(tt.name, func(t *testing.T) {
			if got := equal(s.Name(), dest.Name()); got != tt.want {
				t.Errorf("equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
