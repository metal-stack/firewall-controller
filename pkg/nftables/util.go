package nftables

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func uniqueSorted(elements []string) []string {
	t := map[string]bool{}
	for _, e := range elements {
		t[e] = true
	}
	r := []string{}
	for k := range t {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

func equal(source, target string) bool {
	sourceChecksum, err := checksum(source)
	if err != nil {
		return false
	}

	targetChecksum, err := checksum(target)
	if err != nil {
		return false
	}

	return sourceChecksum == targetChecksum
}

func checksum(file string) (string, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	slices := strings.Split(string(content), "\n")
	sort.Strings(slices)

	h := sha256.New()
	_, err = h.Write([]byte(strings.Join(slices, "\n")))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func assembleDestinationPortRule(common []string, protocol string, ports []string, acceptLog bool, comment string) string {
	logRule := ""
	rule := ""
	parts := common
	parts = append(parts, fmt.Sprintf("%s dport { %s }", protocol, strings.Join(ports, ", ")))
	if acceptLog {
		logParts := append(parts, "log prefix \"nftables-firewall-accepted: \" limit rate 10/second")
		logRule = strings.Join(logParts, " ")
	}
	parts = append(parts, "counter", "accept")
	if comment != "" {
		parts = append(parts, "comment", fmt.Sprintf(`"%s"`, comment))
	}
	rule = strings.Join(parts, " ")
	if logRule != "" {
		rule = logRule + "\n" + rule
	}
	return rule
}

func proto(p *corev1.Protocol) string {
	proto := "tcp"
	if p != nil {
		proto = strings.ToLower(string(*p))
	}
	return proto
}
