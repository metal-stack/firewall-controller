package suricata

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatsParser(t *testing.T) {
	stats := parseStats(sampleStats)
	require.NotNil(t, stats)
	require.Contains(t, stats, "capture.kernel_packets")
	require.Equal(t, stats["capture.kernel_packets"], int64(2))
}

// suricata.yaml need to have the following stats configurations set:
// - stats:
// enabled: yes
// filename: stats.log
// append: no       # append to file (yes) or overwrite it (no)
// totals: yes       # stats for all threads merged together
// threads: no       # per thread stats
// null-values: yes  # print counters that have value 0
var sampleStats = `
------------------------------------------------------------------------------------
Date: 4/24/2020 -- 09:46:41 (uptime: 0d, 00h 01m 28s)
------------------------------------------------------------------------------------
Counter                                       | TM Name                   | Value
------------------------------------------------------------------------------------
capture.kernel_packets                        | Total                     | 2
capture.kernel_drops                          | Total                     | 0
capture.errors                                | Total                     | 0
decoder.pkts                                  | Total                     | 2
decoder.bytes                                 | Total                     | 432
decoder.invalid                               | Total                     | 0
decoder.ipv4                                  | Total                     | 0
decoder.ipv6                                  | Total                     | 0
decoder.ethernet                              | Total                     | 2
decoder.raw                                   | Total                     | 0
decoder.null                                  | Total                     | 0
decoder.sll                                   | Total                     | 0
decoder.tcp                                   | Total                     | 0
decoder.udp                                   | Total                     | 0
decoder.sctp                                  | Total                     | 0
decoder.icmpv4                                | Total                     | 0
decoder.icmpv6                                | Total                     | 0
decoder.ppp                                   | Total                     | 0
decoder.pppoe                                 | Total                     | 0
decoder.gre                                   | Total                     | 0
decoder.vlan                                  | Total                     | 0
decoder.vlan_qinq                             | Total                     | 0
decoder.vxlan                                 | Total                     | 0
decoder.ieee8021ah                            | Total                     | 0
decoder.teredo                                | Total                     | 0
decoder.ipv4_in_ipv6                          | Total                     | 0
decoder.ipv6_in_ipv6                          | Total                     | 0
decoder.mpls                                  | Total                     | 0
decoder.avg_pkt_size                          | Total                     | 216
decoder.max_pkt_size                          | Total                     | 216
decoder.erspan                                | Total                     | 0
flow.memcap                                   | Total                     | 0
flow.tcp                                      | Total                     | 0
flow.udp                                      | Total                     | 0
flow.icmpv4                                   | Total                     | 0
flow.icmpv6                                   | Total                     | 0
defrag.ipv4.fragments                         | Total                     | 0
defrag.ipv4.reassembled                       | Total                     | 0
defrag.ipv4.timeouts                          | Total                     | 0
defrag.ipv6.fragments                         | Total                     | 0
defrag.ipv6.reassembled                       | Total                     | 0
defrag.ipv6.timeouts                          | Total                     | 0
defrag.max_frag_hits                          | Total                     | 0
decoder.event.ipv4.pkt_too_small              | Total                     | 0
decoder.event.ipv4.hlen_too_small             | Total                     | 0
decoder.event.ipv4.iplen_smaller_than_hlen    | Total                     | 0
decoder.event.ipv4.trunc_pkt                  | Total                     | 0
decoder.event.ipv4.opt_invalid                | Total                     | 0
decoder.event.ipv4.opt_invalid_len            | Total                     | 0
decoder.event.ipv4.opt_malformed              | Total                     | 0
decoder.event.ipv4.opt_pad_required           | Total                     | 0
decoder.event.ipv4.opt_eol_required           | Total                     | 0
decoder.event.ipv4.opt_duplicate              | Total                     | 0
decoder.event.ipv4.opt_unknown                | Total                     | 0
decoder.event.ipv4.wrong_ip_version           | Total                     | 0
decoder.event.ipv4.icmpv6                     | Total                     | 0
decoder.event.icmpv4.pkt_too_small            | Total                     | 0
decoder.event.icmpv4.unknown_type             | Total                     | 0
decoder.event.icmpv4.unknown_code             | Total                     | 0
decoder.event.icmpv4.ipv4_trunc_pkt           | Total                     | 0
decoder.event.icmpv4.ipv4_unknown_ver         | Total                     | 0
decoder.event.icmpv6.unknown_type             | Total                     | 0
decoder.event.icmpv6.unknown_code             | Total                     | 0
decoder.event.icmpv6.pkt_too_small            | Total                     | 0
decoder.event.icmpv6.ipv6_unknown_version     | Total                     | 0
decoder.event.icmpv6.ipv6_trunc_pkt           | Total                     | 0
decoder.event.icmpv6.mld_message_with_invalid_hl | Total                     | 0
`
