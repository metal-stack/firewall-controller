package dns

type DNSCache struct {
	nameToIPs map[string][]string
}
